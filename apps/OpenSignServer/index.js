import dotenv from 'dotenv';
dotenv.config();
import express from 'express';
import cors from 'cors';
import { ParseServer } from 'parse-server';
import path from 'path';
const __dirname = path.resolve();
import http from 'http';
import formData from 'form-data';
import Mailgun from 'mailgun.js';
import { ApiPayloadConverter } from 'parse-server-api-mail-adapter';
import S3Adapter from '@parse/s3-files-adapter';
import FSFilesAdapter from '@parse/fs-files-adapter';
import sendgrid from '@sendgrid/mail';
import AWS from 'aws-sdk';
import { app as customRoute } from './cloud/customRoute/customApp.js';
import { exec } from 'child_process';
import { createTransport } from 'nodemailer';
import { app as v1 } from './cloud/customRoute/v1/apiV1.js';
import { PostHog } from 'posthog-node';
import { appName, cloudServerUrl, smtpenable, smtpsecure, useLocal } from './Utils.js';
import { SSOAuth } from './auth/authadapter.js';
import mongoose from 'mongoose';
import { normalizeParseSessionHeaders } from './security/parseSessionAuth.js';
import { captchaParseAuthMiddleware } from './security/captcha.js';

const presignedUrlExpiresSeconds = Number(process.env.PRESIGNED_URL_EXPIRES_SECONDS || 160);
let fsAdapter;
if (useLocal !== 'true') {
  try {
    // S3 requires SigV4 in every region created after Jan 2014 (e.g. us-east-2);
    // aws-sdk v2 otherwise falls back to SigV2 for presigned URLs and S3 answers 400.
    const s3overrides = { signatureVersion: 'v4' };
    if (process.env.DO_ENDPOINT) {
      s3overrides.endpoint = new AWS.Endpoint(process.env.DO_ENDPOINT);
    }
    if (process.env.DO_ACCESS_KEY_ID && process.env.DO_SECRET_ACCESS_KEY) {
      s3overrides.accessKeyId = process.env.DO_ACCESS_KEY_ID;
      s3overrides.secretAccessKey = process.env.DO_SECRET_ACCESS_KEY;
    }

    const s3Options = {
      bucket: process.env.DO_SPACE,
      baseUrl: process.env.DO_BASEURL,
      fileAcl: 'none',
      region: process.env.DO_REGION,
      directAccess: true,
      preserveFileName: true,
      presignedUrl: true,
      presignedUrlExpires: presignedUrlExpiresSeconds,
    };
    if (Object.keys(s3overrides).length > 0) {
      s3Options.s3overrides = s3overrides;
    }
    fsAdapter = new S3Adapter(s3Options);
  } catch (err) {
    console.log('Please provide AWS credintials in env file! Defaulting to local storage.');
    fsAdapter = new FSFilesAdapter({
      filesSubDirectory: 'files', // optional, defaults to ./files
    });
  }
} else {
  fsAdapter = new FSFilesAdapter({
    filesSubDirectory: 'files', // optional, defaults to ./files
  });
}

let transporterMail;
let mailgunClient;
let mailgunDomain;
let isMailAdapter = false;
if (smtpenable) {
  try {
    transporterMail = createTransport({
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT || 465,
      secure: smtpsecure,
      auth: {
        user: process.env.SMTP_USERNAME ? process.env.SMTP_USERNAME : process.env.SMTP_USER_EMAIL,
        pass: process.env.SMTP_PASS,
      },
    });
    await transporterMail.verify();
    isMailAdapter = true;
  } catch (err) {
    isMailAdapter = false;
    console.log('Please provide valid SMTP credentials');
  }
} else if (process.env.MAILGUN_API_KEY) {
  try {
    const mailgun = new Mailgun(formData);
    mailgunClient = mailgun.client({
      username: 'api',
      key: process.env.MAILGUN_API_KEY,
    });
    mailgunDomain = process.env.MAILGUN_DOMAIN;
    isMailAdapter = true;
  } catch (error) {
    isMailAdapter = false;
    console.log('Please provide valid Mailgun credentials');
  }
} else if (process.env.SENDGRID_API_KEY) {
  sendgrid.setApiKey(process.env.SENDGRID_API_KEY);
  isMailAdapter = true;
}
const mailsender = ''; //smtpenable ? process.env.SMTP_USER_EMAIL : process.env.MAILGUN_SENDER;
export const config = {
  databaseURI:
    process.env.DATABASE_URI || process.env.MONGODB_URI || 'mongodb://localhost:27017/dev',
  cloud: function () {
    import('./cloud/main.js');
  },
  appId: process.env.APP_ID || 'effisign',
  logLevel: ['error'],
  maxLimit: 500,
  maxUploadSize: '30mb',
  masterKey: process.env.MASTER_KEY, //Add your master key here. Keep it secret!
  masterKeyIps: ['0.0.0.0/0', '::/0'], // '::1'
  serverURL: cloudServerUrl, // Don't forget to change to https if needed
  verifyUserEmails: false,
  publicServerURL: process.env.SERVER_URL || cloudServerUrl,
  // Your apps name. This will appear in the subject and body of the emails that are sent.
  appName: appName,
  allowClientClassCreation: false,
  allowExpiredAuthDataToken: false,
  encodeParseObjectInCloudFunction: true,
  ...(isMailAdapter === true
    ? {
        emailAdapter: {
          module: 'parse-server-api-mail-adapter',
          options: {
            // The email address from which emails are sent.
            sender: appName + ' <' + mailsender + '>',
            // The email templates.
            templates: {
              // The template used by Parse Server to send an email for password
              // reset; this is a reserved template name.
              passwordResetEmail: {
                subjectPath: './files/password_reset_email_subject.txt',
                textPath: './files/password_reset_email.txt',
                htmlPath: './files/password_reset_email.html',
              },
              // The template used by Parse Server to send an email for email
              // address verification; this is a reserved template name.
              verificationEmail: {
                subjectPath: './files/verification_email_subject.txt',
                textPath: './files/verification_email.txt',
                htmlPath: './files/verification_email.html',
              },
            },
            apiCallback: async ({ payload, locale }) => {
              if (mailgunClient) {
                const mailgunPayload = ApiPayloadConverter.mailgun(payload);
                await mailgunClient.messages.create(mailgunDomain, mailgunPayload);
              } else if (process.env.SENDGRID_API_KEY) {
                await sendgrid.send(payload);
              } else if (transporterMail) await transporterMail.sendMail(payload);
            },
          },
        },
      }
    : {}),
  filesAdapter: fsAdapter,
  auth: { google: { enabled: true }, sso: SSOAuth },
};
// Client-keys like the javascript key or the .NET key are not necessary with parse-server
// If you wish you require them, you can set them as options in the initialization above:
// javascriptKey, restAPIKey, dotNetKey, clientKey

export const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(normalizeParseSessionHeaders);
app.use(function (req, res, next) {
  req.headers['x-real-ip'] = getUserIP(req);
  next();
});
function getUserIP(request) {
  let forwardedFor = request.headers['x-forwarded-for'];
  if (forwardedFor) {
    if (forwardedFor.indexOf(',') > -1) {
      return forwardedFor.split(',')[0];
    } else {
      return forwardedFor;
    }
  } else {
    return request.socket.remoteAddress;
  }
}
app.use(function (req, res, next) {
  const ph_project_api_key = process.env.PH_PROJECT_API_KEY;
  try {
    req.posthog = new PostHog(ph_project_api_key);
  } catch (err) {
    // console.log('Err', err);
    req.posthog = '';
  }
  next();
});
// Serve static assets from the /public folder
app.use('/public', express.static(path.join(__dirname, '/public')));

// Serve the Parse API on the /parse URL prefix
if (!process.env.TESTING) {
  const mountPath = process.env.PARSE_MOUNT || '/app';
  try {
    const server = new ParseServer(config);
    await server.start();
    app.use(mountPath, captchaParseAuthMiddleware());
    app.use(mountPath, server.app);
  } catch (err) {
    console.log(err);
  }
}
// Mount your custom express app
app.use('/', customRoute);

// Mount v1
app.use('/v1', v1);

// Parse Server plays nicely with the rest of your web routes
app.get('/', function (req, res) {
  res.status(200).send('effisign-server is running !!!');
});

mongoose.connect(config.databaseURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
app.get('/health', async function (req, res) {
  try {
    // Check MongoDB connection
    if (mongoose.connection.readyState !== 1) {
      throw new Error('MongoDB not connected');
    }

    // Optionally perform a test query
    await mongoose.connection.db.command({ ping: 1 });

    res.status(200).json({
      status: 'ok',
      uptime: process.uptime(),
      timestamp: new Date(),
    });
  } catch (error) {
    res.status(503).json({
      status: 'error',
      message: error.message,
      uptime: process.uptime(),
      timestamp: new Date(),
    });
  }
});

if (!process.env.TESTING) {
  const port = process.env.PORT || 8080;
  const httpServer = http.createServer(app);
  // Set the Keep-Alive and headers timeout to 100 seconds
  httpServer.keepAliveTimeout = 100000; // in milliseconds
  httpServer.headersTimeout = 100000; // in milliseconds
  httpServer.listen(port, '0.0.0.0', function () {
    console.log('effisign-server running on port ' + port + '.');
    const isWindows = process.platform === 'win32';
    // console.log('isWindows', isWindows);

    const migrate = isWindows
      ? `set APPLICATION_ID=${process.env.APP_ID}&& set SERVER_URL=${cloudServerUrl}&& set MASTER_KEY=${process.env.MASTER_KEY}&& npx parse-dbtool migrate`
      : `APPLICATION_ID=${process.env.APP_ID} SERVER_URL=${cloudServerUrl} MASTER_KEY=${process.env.MASTER_KEY} npx parse-dbtool migrate`;
    exec(migrate, (error, stdout, stderr) => {
      if (error) {
        console.error(`Error: ${error.message}`);
        return;
      }

      if (stderr) {
        console.error(`Error: ${stderr}`);
        return;
      }
      console.log(`Command output: ${stdout}`);
    });
  });
}
