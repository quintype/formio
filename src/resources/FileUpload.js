"use strict";
const crypto = require("crypto");

const createHmacDigest = (key, string) => {
  const hmac = crypto.createHmac("sha256", key);
  hmac.write(string);
  hmac.end();
  return hmac.read();
};

const generateFileSignature = async (req, res) => {
  const { name } = req.body;
  const fileName = name;

  const config = {
    bucket: process.env.AWS_BUCKET,
    region: process.env.AWS_REGION,
    acl: "public-read",
    accessKey: process.env.AWS_ACCESS_KEY_ID,
    secretKey: process.env.AWS_SECRET_ACCESS_KEY,
    "x-amz-algorithm": "AWS4-HMAC-SHA256",
    successActionStatus: "201",
  };

  const uploadUrl = `https://${config.bucket}.s3.amazonaws.com`;

  const date = new Date().toISOString();

  // create date string for the current date
  const dateString = date.substr(0, 4) + date.substr(5, 2) + date.substr(8, 2);

  // create upload credentials
  const credential = `${config.accessKey}/${dateString}/${config.region}/s3/aws4_request`;

  // create policy
  const policy = {
    expiration: new Date(new Date().getTime() + 1 * 60 * 1000).toISOString(), // to set the time after which upload will no longer be allowed using this policy
    conditions: [
      { bucket: config.bucket },
      { key: fileName }, // fileName with which the uploaded file will be saved on s3
      { acl: config.acl },
      { success_action_status: config.successActionStatus },
      ["content-length-range", 0, 1000000], // optional: to specify the minimum and maximum upload limit
      { "x-amz-algorithm": config["x-amz-algorithm"] },
      { "x-amz-credential": credential },
      { "x-amz-date": `${dateString}T000000Z` },
      { fileName },
    ],
  };

  // base64 encode policy
  const policyBase64 = new Buffer(JSON.stringify(policy)).toString("base64");

  // create signature with policy, aws secret key & other scope information
  const dateKey = createHmacDigest(`AWS4${config.secretKey}`, dateString);
  const dateRegionKey = createHmacDigest(dateKey, config.region);
  const dateRegionServiceKey = createHmacDigest(dateRegionKey, "s3");
  const signingKey = createHmacDigest(dateRegionServiceKey, "aws4_request");

  // sign policy document with the signing key to generate upload signature
  const xAmzSignature = createHmacDigest(signingKey, policyBase64).toString(
    "hex"
  );

  res.json({
    url: uploadUrl,
    data: {
      key: "",
      acl: config.acl,
      success_action_status: config.successActionStatus,
      policy: policyBase64,
      "x-amz-algorithm": config["x-amz-algorithm"],
      "x-amz-credential": credential,
      "x-amz-date": `${dateString}T000000Z`,
      "x-amz-signature": xAmzSignature,
    },
  });
};

module.exports = generateFileSignature;
