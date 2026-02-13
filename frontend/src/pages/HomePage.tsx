const HomePage = () => {
  return (
    <div className="card">
      <header className="home-header">
        <h1 className="home-title">Welcome to CodeGraph</h1>
        <p className="home-subtitle">
          Your intelligent companion for secure, compliant, and queryable Java
          codebases.
        </p>
      </header>

      <div className="home-grid">
        <div className="feature-card">
          <h3 className="feature-title">Ingest & Index</h3>
          <p className="text-sm">
            Parses Java source code into a Neo4j graph and builds semantic
            embeddings for hybrid search.
          </p>
        </div>

        <div className="feature-card">
          <h3 className="feature-title">Semantic Search</h3>
          <p className="text-sm">
            Find code using natural language queries, enriched with graph-based
            context.
          </p>
        </div>

        <div className="feature-card">
          <h3 className="feature-title">Policy Evaluation</h3>
          <p className="text-sm">
            Automated ISO 27001 compliance checks with LLM-powered remediation
            suggestions.
          </p>
        </div>
      </div>

      <div className="config-tip">
        <strong>Configuration Tip:</strong> Ensure the backend is running at{" "}
        <code className="code-snippet">http://127.0.0.1:8000</code> or set{" "}
        <code>VITE_API_BASE_URL</code>.
      </div>
    </div>
  );
};

export default HomePage;
