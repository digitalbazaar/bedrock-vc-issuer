const sinon = require('sinon');
const brPassport = require('bedrock-passport');
const {profileAgents} = require('bedrock-profile');

async function createIssuerInstance() {
  const instance = await profileAgents.create(
    {accountId: 'foo'});
  return instance;
}

async function createIntegrationInstance({instanceId}) {
  const integration = await profileAgents.create(
    {profileId: instanceId, token: 'foo'});
}

async function insertIssuerAgent() {
  const instance = await profileAgents.create(
    {accountId: 'foo'});
console.log('instance', instance);
  const integration = await profileAgents.create(
    {profileId: instance.id, token: 'foo'});
console.log('integration', integration);
  return {instance, integration};
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
