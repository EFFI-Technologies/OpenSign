const className = 'contracts_Template';

const reminderFields = [
  {
    name: 'RemindOnceInEvery',
    add: schema => schema.addNumber('RemindOnceInEvery'),
  },
  {
    name: 'NextReminderDate',
    add: schema => schema.addDate('NextReminderDate'),
  },
];

async function updateReminderFields(Parse, mode) {
  const currentSchema = await new Parse.Schema(className).get();
  const schema = new Parse.Schema(className);
  let hasChanges = false;

  for (const field of reminderFields) {
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
  return updateReminderFields(Parse, 'add');
};

/**
 *
 * @param {Parse} Parse
 */
exports.down = async Parse => {
  return updateReminderFields(Parse, 'delete');
};
