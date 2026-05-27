function assertSignatureOwner(request) {
  if (request.master) {
    return;
  }
  if (!request.user) {
    throw new Parse.Error(Parse.Error.SESSION_MISSING, 'Signature changes require authentication.');
  }

  const originalUserId = request.original?.get('UserId')?.id;
  if (originalUserId && originalUserId !== request.user.id) {
    throw new Parse.Error(Parse.Error.OPERATION_FORBIDDEN, 'Cannot modify another user signature.');
  }

  const userPointer = Parse.User.createWithoutData(request.user.id);
  const acl = new Parse.ACL();
  acl.setReadAccess(request.user, true);
  acl.setWriteAccess(request.user, true);

  request.object.set('UserId', userPointer);
  request.object.setACL(acl);
}

export default assertSignatureOwner;
