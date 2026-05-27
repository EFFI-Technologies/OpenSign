const { classLevelPermissions } = require('../../security/parseClassLevelPermissions.cjs');

async function saveOrUpdateCLP(Parse, className, clp) {
  const schema = new Parse.Schema(className);
  schema.setCLP(clp);

  try {
    await schema.update();
  } catch (err) {
    const message = err?.message || '';
    if (!/schema|class|not found|does not exist/i.test(message)) {
      throw err;
    }

    const newSchema = new Parse.Schema(className);
    newSchema.setCLP(clp);
    await newSchema.save();
  }
}

/**
 *
 * @param {Parse} Parse
 */
exports.up = async Parse => {
  for (const [className, clp] of Object.entries(classLevelPermissions)) {
    await saveOrUpdateCLP(Parse, className, clp);
  }
};

/**
 *
 * @param {Parse} Parse
 */
exports.down = async Parse => {
  // Intentionally left in place. Rolling this migration back would restore public appId-only CRUD.
};
