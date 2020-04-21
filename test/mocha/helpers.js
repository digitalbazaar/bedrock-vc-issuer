const sinon = require('sinon');
const brPassport = require('bedrock-passport');
const {profiles, profileAgents} = require('bedrock-profile');

async function insertIssuerAgent() {
  const profile = await profiles.create(
    {accountId: 'foo'});
  const integration = await profileAgents.create(
    {profileId: profile.id, token: 'test-issuer'});
  return {instance: profile, integration};
}

exports.stubPassport = ({actor}) => {
  const passportStub = sinon.stub(brPassport, 'optionallyAuthenticated');
  passportStub.callsFake((req, res, next) => {
    req.user = {
      account: {},
      actor,
    };
    next();
  });
  return passportStub;
};

exports.insertIssuerAgent = insertIssuerAgent;
