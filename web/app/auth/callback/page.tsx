'use client';
import { useEffect, useState } from 'react';
import { ErrorBox } from '@/components/ui';
import { finishLogin } from '@/lib/oidc';
import { saveSession } from '@/lib/session';

export default function Callback() {
  const [err, setErr] = useState<unknown>(null);
  useEffect(() => {
    finishLogin(window.location.search).then(
      (s) => { saveSession(s); window.location.replace('/'); },
      setErr,
    );
  }, []);
  return (
    <main className="mx-auto mt-16 max-w-md space-y-3 p-4">
      <ErrorBox error={err} />
      {err ? <a className="underline" href="/login/">Back to login</a> : <p className="text-sm text-zinc-500">Completing sign-in…</p>}
    </main>
  );
}
