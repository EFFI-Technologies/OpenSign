const className = 'contracts_Document';

const documentDeliveryFields = [
  {
    name: 'NextReminderDate',
    add: schema => schema.addDate('NextReminderDate'),
  },
  {
    name: 'DocSentAt',
    add: schema => schema.addDate('DocSentAt'),
  },
  {
    name: 'IsSendMail',
    add: schema => schema.addBoolean('IsSendMail'),
  },
  {
    name: 'CertificateUrl',
    add: schema => schema.addString('CertificateUrl'),
  },
];

async function updateDocumentDeliveryFields(Parse, mode) {
  const currentSchema = await new Parse.Schema(className).get();
  const schema = new Parse.Schema(className);
  let hasChanges = false;

  for (const field of documentDeliveryFields) {
    const fieldExists = Boolean(currentSchema.fields?.[field.name]);

    if (mode === 'add' && !fieldExists) {
      field.add(schema);
      hasChanges = true;
    }

    if (mode === 'delete' && fieldExists) {
      schema.deleteField(field.name);
      hasChanges = true;
    }
  }

  if (!hasChanges) {
    return;
  }

  return schema.update();
}

/**
 *
 * @param {Parse} Parse
 */
exports.up = async Parse => {
  return updateDocumentDeliveryFields(Parse, 'add');
};

/**
 *
 * @param {Parse} Parse
 */
exports.down = async Parse => {
  return updateDocumentDeliveryFields(Parse, 'delete');
};
