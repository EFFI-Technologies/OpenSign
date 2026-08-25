import AWS from 'aws-sdk';
import { useLocal } from '../../Utils.js';
import { getRequestUser } from '../../security/parseSessionAuth.js';

const presignedUrlExpiresSeconds = Number(process.env.PRESIGNED_URL_EXPIRES_SECONDS || 160);
const protectedUrlFields = ['URL', 'SignedUrl', 'CertificateUrl'];

function getPointerId(pointer) {
  return pointer?.id || pointer?.objectId || pointer?.get?.('objectId') || '';
}

function getObjectKey(url) {
  if (!url) {
    return '';
  }

  try {
    const parsedUrl = new URL(url);
    const pathname = decodeURIComponent(parsedUrl.pathname || '');
    return pathname.substring(pathname.lastIndexOf('/') + 1);
  } catch {
    return '';
  }
}

function getCredentials(accessKeyId, secretAccessKey) {
  if (accessKeyId && secretAccessKey) {
    return new AWS.Credentials({ accessKeyId, secretAccessKey });
  }
  return undefined;
}

function getTenantFileAdapter(record, fileAdapterId) {
  if (!fileAdapterId) {
    return {};
  }

  const adapterConfig = findTenantFileAdapter(record, fileAdapterId);
  if (!adapterConfig) {
    throw new Parse.Error(Parse.Error.OBJECT_NOT_FOUND, 'File adapter not found.');
  }
  return adapterConfig;
}

function findTenantFileAdapter(record, fileAdapterId) {
  const tenant = record?.get('ExtUserPtr')?.get('TenantId');
  const fileAdapters = tenant?.get('FileAdapters') || [];
  return fileAdapters.find(x => x.id === fileAdapterId);
}

function isRequestedUrlStoredOnRecord(record, requestedUrl) {
  const requestedKey = getObjectKey(requestedUrl);
  if (!requestedKey) {
    return false;
  }

  return protectedUrlFields.some(field => getObjectKey(record?.get(field)) === requestedKey);
}

async function getCurrentExtUser(userId) {
  if (!userId) {
    return null;
  }

  const extUserQuery = new Parse.Query('contracts_Users');
  extUserQuery.equalTo('UserId', {
    __type: 'Pointer',
    className: '_User',
    objectId: userId,
  });
  extUserQuery.include('TeamIds');
  return extUserQuery.first({ useMasterKey: true });
}

function hasAclReadAccess(record, userId) {
  const acl = record?.getACL?.();
  return Boolean(userId && acl?.getReadAccess(userId));
}

function getTeamIdsFromExtUser(extUser) {
  const teams = extUser?.get('TeamIds') || [];
  return teams.flatMap(team => {
    const ancestors = team?.get?.('Ancestors') || team?.Ancestors || [];
    return ancestors.map(getPointerId).filter(Boolean);
  });
}

function templateSharedWithTeams(template, teamIds) {
  const sharedWith = template?.get('SharedWith') || [];
  const sharedTeamIds = sharedWith.map(getPointerId).filter(Boolean);
  return teamIds.some(teamId => sharedTeamIds.includes(teamId));
}

async function canReadPrivateTarget(record, targetClass, userId) {
  if (hasAclReadAccess(record, userId)) {
    return true;
  }

  if (targetClass !== 'contracts_Template') {
    return false;
  }

  const extUser = await getCurrentExtUser(userId);
  const ownerExtUserId = getPointerId(record?.get('ExtUserPtr'));
  if (extUser?.id && ownerExtUserId === extUser.id) {
    return true;
  }

  const teamIds = getTeamIdsFromExtUser(extUser);
  return templateSharedWithTeams(record, teamIds);
}

async function loadTargetRecord({ docId, templateId }) {
  const targetClass = docId ? 'contracts_Document' : 'contracts_Template';
  const objectId = docId || templateId;
  const query = new Parse.Query(targetClass);
  query.equalTo('objectId', objectId);
  query.include('ExtUserPtr');
  query.include('ExtUserPtr.TenantId');
  query.notEqualTo('IsArchive', true);
  const record = await query.first({
    useMasterKey: true,
    context: { skipPresign: true },
  });

  if (!record) {
    throw new Parse.Error(Parse.Error.OBJECT_NOT_FOUND, 'Object not found.');
  }

  return { record, targetClass };
}

async function assertCanMintSignedUrl(request, record, targetClass) {
  const user = await getRequestUser(request);
  const isPublicTarget =
    targetClass === 'contracts_Document'
      ? record?.get('IsEnableOTP') !== true
      : record?.get('IsPublic') === true;

  if (isPublicTarget) {
    return;
  }

  if (!user) {
    throw new Parse.Error(Parse.Error.INVALID_SESSION_TOKEN, 'User is not authenticated.');
  }

  const canRead = await canReadPrivateTarget(record, targetClass, user.id);
  if (!canRead) {
    throw new Parse.Error(Parse.Error.OPERATION_FORBIDDEN, "You don't have access.");
  }
}

export default function getPresignedUrl(url, adapter) {
  const accessKeyId = adapter?.accessKeyId || process.env.DO_ACCESS_KEY_ID;
  const secretAccessKey = adapter?.secretAccessKey || process.env.DO_SECRET_ACCESS_KEY;
  const endpoint = adapter?.endpoint || process.env.DO_ENDPOINT;
  const region = adapter?.region || process.env.DO_REGION;
  const s3Options = {
    // S3 requires SigV4 in every region created after Jan 2014 (e.g. us-east-2);
    // aws-sdk v2 otherwise falls back to SigV2 for presigned URLs and S3 answers 400.
    signatureVersion: 'v4',
    region,
  };
  const credentials = getCredentials(accessKeyId, secretAccessKey);
  if (credentials) {
    s3Options.credentials = credentials;
  }

  if (endpoint) {
    s3Options.endpoint = new AWS.Endpoint(endpoint);
  }

  const s3 = new AWS.S3(s3Options);

  // Create a new URL object
  const parsedUrl = new URL(url);
  // Get the pathname of the URL
  const pathname = parsedUrl.pathname;
  // Extract the filename from the pathname
  const filename = pathname.substring(pathname.lastIndexOf('/') + 1);

  // presignedGETURL return presignedUrl with expires time
  const presignedGETURL = s3.getSignedUrl('getObject', {
    Bucket: adapter?.bucketName || process.env.DO_SPACE,
    Key: filename, //filename
    Expires: presignedUrlExpiresSeconds,
  });
  return presignedGETURL;
}

export function applyPresignedUrlsToRecord(record) {
  const fileAdapterId = record?.get('FileAdapterId') || '';
  if (!fileAdapterId && useLocal === 'true') {
    return record;
  }

  const adapterConfig = fileAdapterId ? findTenantFileAdapter(record, fileAdapterId) || {} : {};
  for (const field of protectedUrlFields) {
    const storedUrl = record?.get(field);
    if (storedUrl) {
      record.set(field, getPresignedUrl(storedUrl, adapterConfig));
    }
  }

  return record;
}

export async function getSignedUrl(request) {
  try {
    const docId = request.params.docId || '';
    const templateId = request.params.templateId || '';
    const url = request.params.url;
    const fileAdapterId = request.params.fileAdapterId || '';
    if (!url) {
      throw new Parse.Error(Parse.Error.INVALID_QUERY, 'Please provide url.');
    }
    if (docId || templateId) {
      try {
        const { record, targetClass } = await loadTargetRecord({ docId, templateId });
        if (!isRequestedUrlStoredOnRecord(record, url)) {
          throw new Parse.Error(Parse.Error.OPERATION_FORBIDDEN, "You don't have access.");
        }

        await assertCanMintSignedUrl(request, record, targetClass);

        if (fileAdapterId || useLocal !== 'true') {
          const adapterConfig = getTenantFileAdapter(record, fileAdapterId);
          const presignedUrl = getPresignedUrl(url, adapterConfig);
          return presignedUrl;
        } else {
          return url;
        }
      } catch (err) {
        console.log('Err in presigned url', err);
        throw err;
      }
    } else {
      throw new Parse.Error(Parse.Error.INVALID_QUERY, 'Please provide document or template id.');
    }
  } catch (err) {
    console.log('error in getsignedurl', err);
    const code = err.code || 400;
    const msg = err.message;
    const error = new Parse.Error(code, msg);
    throw error;
  }
}
