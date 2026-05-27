const operations = ['get', 'find', 'count', 'create', 'update', 'delete', 'addField'];

function emptyOperationMap() {
  return Object.fromEntries(operations.map(operation => [operation, {}]));
}

function masterKeyOnlyCLP() {
  return emptyOperationMap();
}

function authenticatedUsersCLP() {
  return {
    get: { requiresAuthentication: true },
    find: { requiresAuthentication: true },
    count: { requiresAuthentication: true },
    create: { requiresAuthentication: true },
    update: { requiresAuthentication: true },
    delete: { requiresAuthentication: true },
    addField: {},
  };
}

function pointerOwnerCLP(readUserFields, writeUserFields = readUserFields) {
  return {
    get: {},
    find: {},
    count: {},
    create: { requiresAuthentication: true },
    update: {},
    delete: {},
    addField: {},
    readUserFields,
    writeUserFields,
  };
}

function withProtectedFields(clp, protectedFields) {
  return {
    ...clp,
    protectedFields,
  };
}

const classLevelPermissions = {
  partners_Tenant: withProtectedFields(masterKeyOnlyCLP(), {
    '*': ['FileAdapters', 'PfxFile'],
    requiresAuthentication: ['FileAdapters', 'PfxFile'],
  }),
  partners_TenantCredits: authenticatedUsersCLP(),
  partners_DataFiles: authenticatedUsersCLP(),
  contracts_Contactbook: pointerOwnerCLP(['CreatedBy', 'UserId'], ['CreatedBy', 'UserId']),
  contracts_Signature: pointerOwnerCLP(['UserId'], ['UserId']),
  contracts_Webhook: masterKeyOnlyCLP(),
  contracts_Document: authenticatedUsersCLP(),
  contracts_Template: authenticatedUsersCLP(),
  contracts_Users: authenticatedUsersCLP(),
  contracts_Teams: masterKeyOnlyCLP(),
  contracts_Organizations: masterKeyOnlyCLP(),
  contracts_Subscriptions: masterKeyOnlyCLP(),
  contracts_Payments: masterKeyOnlyCLP(),
  contracts_Invoices: masterKeyOnlyCLP(),
  appToken: masterKeyOnlyCLP(),
};

module.exports = {
  authenticatedUsersCLP,
  classLevelPermissions,
  masterKeyOnlyCLP,
  pointerOwnerCLP,
  withProtectedFields,
};
