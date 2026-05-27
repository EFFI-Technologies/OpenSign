const className = 'contracts_Template';
const fieldName = 'FileAdapterId';

async function updateTemplateFileAdapterField(Parse, mode) {
  const currentSchema = await new Parse.Schema(className).get();
  const schema = new Parse.Schema(className);
  const fieldExists = Boolean(currentSchema.fields?.[fieldName]);

  if (mode === 'add' && !fieldExists) {
    schema.addString(fieldName);
    return schema.update();
  }

  if (mode === 'delete' && fieldExists) {
    schema.deleteField(fieldName);
    return schema.update();
  }
}

/**
 *
 * @param {Parse} Parse
 */
exports.up = async Parse => {
  return updateTemplateFileAdapterField(Parse, 'add');
};

/**
 *
 * @param {Parse} Parse
 */
exports.down = async Parse => {
  return updateTemplateFileAdapterField(Parse, 'delete');
};
