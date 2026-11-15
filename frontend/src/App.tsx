// PoisonLens v2 app shell. The upload-first screens (spec section 7) are built in Phase 11.

const STAGES = ['Upload', 'Inspect', 'Security', 'Quality', 'Probe', 'Detect', 'Sanitize', 'Seal'] as const;

export function App() {
  return (
    <>
      <header className="shell-header">
        <span className="shell-dot" aria-hidden="true" />
        PoisonLens
      </header>
      <main className="shell-main">
        <ol className="stepper" aria-label="Pipeline">
          {STAGES.map((stage) => (
            <li key={stage}>{stage}</li>
          ))}
        </ol>
        <section className="notice">
          <strong>Dataset upload is not available yet.</strong>
          <p>
            PoisonLens is being rebuilt around uploading your own dataset. The scan screens will appear
            here as the backend stages land.
          </p>
        </section>
      </main>
    </>
  );
}

export default App;
