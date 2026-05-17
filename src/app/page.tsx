function CreatePasskeyPanel() {
  return (
    <section className="flex flex-col items-center justify-center gap-6 text-center">
      <button
        type="button"
        className="rounded-2xl bg-black px-16 py-8 text-4xl font-bold tracking-normal text-white shadow-xl transition hover:-translate-y-1 hover:bg-zinc-800 focus:outline-none focus:ring-4 focus:ring-zinc-400 active:translate-y-0 sm:px-24 sm:py-10 sm:text-6xl"
      >
        Create passkey
      </button>
    </section>
  );
}

export default function Home() {
  return (
    <main className="flex min-h-screen items-center justify-center bg-white p-6">
      <CreatePasskeyPanel />
    </main>
  );
}
