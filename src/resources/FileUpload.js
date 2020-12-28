"use strict";
const crypto = require("crypto");
const AWS = require("aws-sdk");

const SUCCESS_ACTION_STATUS = "201";
const ACL = "public-read";

const generatePolicy = (
  fileName,
  fileType,
  AWSBucket,
  expirationTimeout = 60
) => {
  const s3Policy = {
    expiration: new Date(
      new Date().getTime() + 1 * expirationTimeout * 1000
    ).toISOString(),
    conditions: [
      ["starts-with", "$key", fileName],
      {bucket: AWSBucket},
      {acl: ACL},
      ["starts-with", "$Content-Type", fileType],
      {'success_action_status': SUCCESS_ACTION_STATUS},
      {fileName},
    ],
  };
  const stringPolicy = JSON.stringify(s3Policy);
  const base64Policy = Buffer.from(stringPolicy, "utf-8").toString("base64");
  return base64Policy;
};

const generateSignature = (AWSSecretKey, policy) => {
  return crypto
    .createHmac("sha1", AWSSecretKey)
    .update(Buffer.from(policy, "utf-8"))
    .digest("base64");
};

const sign = async (req, res) => {
  const {name, type} = req.body;
  const fileName = name;
  const fileType = type;

  // Get AWS credentials
  const awsConfig = new AWS.Config();

  const config = {
    bucket: process.env.AWS_BUCKET,
    accessKey: awsConfig.credentials.accessKeyId,
    secretKey: awsConfig.credentials.secretAccessKey,
  };

  // Generate policy
  const policy = generatePolicy(fileName, fileType, config.bucket);

  // Sign the base64 encoded policy
  const signature = generateSignature(config.secretKey, policy);

  res.json({
    url: `https://${config.bucket}.s3.amazonaws.com`,
    data: {
      key: "",
      acl: ACL,
      'success_action_status': SUCCESS_ACTION_STATUS,
      policy: policy,
      AWSAccessKeyId: config.accessKey,
      signature,
      "Content-Type": fileType,
    },
  });
};

module.exports = sign;
