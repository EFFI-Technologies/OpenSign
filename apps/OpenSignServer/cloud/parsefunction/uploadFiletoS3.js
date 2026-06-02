import { S3Client, PutObjectCommand, GetObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import * as crypto from 'node:crypto';

const presignedUrlExpiresSeconds = Number(process.env.PRESIGNED_URL_EXPIRES_SECONDS || 160);

function getS3ClientOptions(adapter) {
  const options = {
    region: adapter?.region,
  };

  if (adapter?.endpoint) {
    options.endpoint = adapter.endpoint;
  }

  if (adapter?.accessKeyId && adapter?.secretAccessKey) {
    options.credentials = {
      accessKeyId: adapter.accessKeyId,
      secretAccessKey: adapter.secretAccessKey,
    };
  }

  return options;
}

async function uploadFileToS3(buffer, fileName, mimeType, adapter) {
  const bucketName = adapter?.bucketName;
  const client = new S3Client(getS3ClientOptions(adapter));
  const prefixId = crypto.randomBytes(16).toString('hex');
  const fileKey = `${prefixId}_${fileName}`;
  const uploadParams = { Bucket: bucketName, Key: fileKey, Body: buffer, ContentType: mimeType };

  try {
    // Upload the buffer to the Space
    const command = new PutObjectCommand(uploadParams);
    await client.send(command);
    const getCommand = new GetObjectCommand({ Bucket: bucketName, Key: fileKey });

    // Generate a presigned URL for the uploaded file
    const presignedUrl = await getSignedUrl(client, getCommand, {
      expiresIn: presignedUrlExpiresSeconds,
    });
    return presignedUrl;
  } catch (error) {
    console.error('Error uploading file to aws:', error?.message);
    throw error;
  }
}

export default uploadFileToS3;
