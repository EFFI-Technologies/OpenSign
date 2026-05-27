import { requireCurrentExtUser } from '../../security/parseSessionAuth.js';
export default async function getInvoices(request) {
  const limit = request.params.limit || 100;
  const skip = request.params.skip || 0;
  const extUserId = request.params.extUserId;
  try {
    if (!extUserId) {
      return { status: 'error', result: 'Please provide parameter!' };
    }

    const currentExtUser = await requireCurrentExtUser(request);
    if (extUserId !== currentExtUser.id) {
      return { status: 'error', result: 'Unauthorized extUserId!' };
    }

    const invoiceCls = new Parse.Query('contracts_Invoices');
    invoiceCls.equalTo('ExtUserPtr', {
      __type: 'Pointer',
      className: 'contracts_Users',
      objectId: extUserId,
    });
    invoiceCls.limit(limit);
    invoiceCls.skip(skip);
    invoiceCls.descending('createdAt');
    const invoices = await invoiceCls.find({ useMasterKey: true });
    if (invoices?.length > 0) {
      const _invoices = JSON.parse(JSON.stringify(invoices));
      return { status: 'success', result: _invoices };
    } else {
      return { status: 'success', result: [] };
    }
  } catch (err) {
    console.log('Err in get invoices', err.message);
    return { status: 'error', result: err.message };
  }
}
