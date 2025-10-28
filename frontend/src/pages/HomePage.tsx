const HomePage = () => {
  return (
    <section className="card">
      <h1>Welcome to CodeGraph</h1>
      <p>
        This interface lets you upload Java projects, build semantic embeddings,
        explore code relationships, and evaluate policies without leaving your
        browser.
      </p>
      <ul>
        <li>Ingest your Java codebase via the Upload view.</li>
        <li>Run hybrid semantic &amp; graph searches in the Search view.</li>
        <li>
          Check ISO 27001 policies and generate LLM explanations in the Policy
          view.
        </li>
      </ul>
      <p>
        Configure the backend URL with the <code>VITE_API_BASE_URL</code>{" "}
        environment variable if the FastAPI service is not running on{" "}
        <code>http://127.0.0.1:8000</code>.
      </p>
    </section>
  );
};

export default HomePage;
