const { classLevelPermissions } = require('../../security/parseClassLevelPermissions.cjs');

const classes = ['contracts_Contactbook', 'contracts_Signature'];

async function updateCLP(Parse, className) {
  const schema = new Parse.Schema(className);
  schema.setCLP(classLevelPermissions[className]);
  await schema.update();
}

/**
 *
 * @param {Parse} Parse
 */
exports.up = async Parse => {
  for (const className of classes) {
    await updateCLP(Parse, className);
  }
};

/**
 *
 * @param {Parse} Parse
 */
exports.down = async Parse => {
  // Intentionally left in place. Rolling back would re-open anonymous pointer-field probes.
};
