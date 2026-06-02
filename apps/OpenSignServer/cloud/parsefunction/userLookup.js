export function normalizeEmail(email) {
  return String(email || '')
    .trim()
    .toLowerCase();
}

function lookupCandidates(value) {
  const raw = String(value || '').trim();
  const normalized = normalizeEmail(raw);
  return [...new Set([normalized, raw].filter(Boolean))];
}

export async function findUserByEmail(email) {
  const candidates = lookupCandidates(email);
  if (candidates.length === 0) {
    return null;
  }

  for (const candidate of candidates) {
    const emailQuery = new Parse.Query(Parse.User);
    emailQuery.equalTo('email', candidate);
    const byEmail = await emailQuery.first({ useMasterKey: true });
    if (byEmail) {
      return byEmail;
    }

    const usernameQuery = new Parse.Query(Parse.User);
    usernameQuery.equalTo('username', candidate);
    const byUsername = await usernameQuery.first({ useMasterKey: true });
    if (byUsername) {
      return byUsername;
    }
  }

  return null;
}

export async function getUserIdByEmail(email) {
  const user = await findUserByEmail(email);
  return user?.id || null;
}
