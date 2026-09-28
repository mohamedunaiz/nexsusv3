import { initializeApp } from 'firebase/app';
import { getAuth, GoogleAuthProvider, signInWithPopup, signOut } from 'firebase/auth';
import {
  getFirestore,
  doc,
  getDocFromServer,
  setDoc,
  collection,
  getDocs,
  query,
  where,
} from 'firebase/firestore';
import firebaseConfig from '../firebase-applet-config.json';

const app = initializeApp(firebaseConfig);
export const db = getFirestore(app, firebaseConfig.firestoreDatabaseId);
export const auth = getAuth(app);

export enum OperationType {
  CREATE = 'create',
  UPDATE = 'update',
  DELETE = 'delete',
  LIST = 'list',
  GET = 'get',
  WRITE = 'write',
}

export interface FirestoreErrorInfo {
  error: string;
  operationType: OperationType;
  path: string | null;
  authInfo: {
    userId?: string | null;
    email?: string | null;
    emailVerified?: boolean | null;
    isAnonymous?: boolean | null;
    tenantId?: string | null;
    providerInfo?: {
      providerId?: string | null;
      email?: string | null;
    }[];
  };
}

export function handleFirestoreError(error: unknown, operationType: OperationType, path: string | null): never {
  const errInfo: FirestoreErrorInfo = {
    error: error instanceof Error ? error.message : String(error),
    authInfo: {
      userId: auth.currentUser?.uid,
      email: auth.currentUser?.email,
      emailVerified: auth.currentUser?.emailVerified,
      isAnonymous: auth.currentUser?.isAnonymous,
      tenantId: auth.currentUser?.tenantId,
      providerInfo:
        auth.currentUser?.providerData?.map((provider) => ({
          providerId: provider.providerId,
          email: provider.email,
        })) || [],
    },
    operationType,
    path,
  };
  console.error('Firestore Error: ', JSON.stringify(errInfo));
  throw new Error(JSON.stringify(errInfo));
}

export async function testFirestoreConnection(): Promise<boolean> {
  try {
    await getDocFromServer(doc(db, 'test', 'connection'));
    return true;
  } catch (error) {
    if (error instanceof Error && error.message.includes('the client is offline')) {
      console.error('Please check your Firebase configuration.');
      return false;
    }
    // Permission denied on /test/connection is expected under default-deny rules and confirms online connectivity
    return true;
  }
}

// Validate connection on boot when running in browser
if (typeof window !== 'undefined') {
  void testFirestoreConnection();
}

export async function signInWithGooglePopup() {
  const provider = new GoogleAuthProvider();
  const cred = await signInWithPopup(auth, provider);
  const user = cred.user;
  const uid = user.uid.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 128);
  const isDefaultAdmin = user.email === 'friends20052005@gmail.com';
  const role: 'Admin' | 'Analyst' | 'Viewer' = isDefaultAdmin ? 'Admin' : 'Analyst';
  const nowIso = new Date().toISOString();

  try {
    await setDoc(doc(db, 'users', uid), {
      uid,
      name: (user.displayName || 'SOC Operator').slice(0, 120),
      role,
      badge: `SOC-${uid.slice(0, 6).toUpperCase()}`,
      createdAt: nowIso,
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, `users/${uid}`);
  }

  if (user.email) {
    try {
      await setDoc(doc(db, 'users', uid, 'private', 'info'), {
        uid,
        email: user.email.slice(0, 254),
      });
    } catch (error) {
      handleFirestoreError(error, OperationType.WRITE, `users/${uid}/private/info`);
    }
  }

  return {
    uid,
    email: user.email || 'operator@agency.gov',
    name: user.displayName || 'SOC Operator',
    role,
    badge: `SOC-${uid.slice(0, 6).toUpperCase()}`,
  };
}

export async function signOutFirebase() {
  await signOut(auth);
}

export async function syncInvestigationToFirestore(inv: {
  id: string;
  caseNumber: string;
  title: string;
  status: string;
  severity: string;
  assignedAgent: string;
  reportSummary?: string;
  createdAt: string;
  updatedAt: string;
}) {
  if (!auth.currentUser) return;
  const uid = auth.currentUser.uid.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 128);
  const docId = inv.id.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 128);
  const path = `investigations/${docId}`;
  try {
    await setDoc(doc(db, 'investigations', docId), {
      id: docId,
      caseNumber: inv.caseNumber.slice(0, 64),
      title: inv.title.slice(0, 300),
      status: inv.status,
      severity: inv.severity,
      ownerId: uid,
      assignedAgent: inv.assignedAgent.slice(0, 100),
      ...(inv.reportSummary ? { reportSummary: inv.reportSummary.slice(0, 5000) } : {}),
      createdAt: inv.createdAt.slice(0, 64),
      updatedAt: inv.updatedAt.slice(0, 64),
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, path);
  }
}

export async function fetchUserInvestigationsFromFirestore() {
  if (!auth.currentUser) return [];
  const uid = auth.currentUser.uid.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 128);
  const path = 'investigations';
  try {
    const q = query(collection(db, 'investigations'), where('ownerId', '==', uid));
    const snap = await getDocs(q);
    return snap.docs.map((d) => d.data());
  } catch (error) {
    handleFirestoreError(error, OperationType.LIST, path);
  }
}
