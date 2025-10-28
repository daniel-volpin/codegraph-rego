from pydantic import BaseSettings, Field

class Settings(BaseSettings):
    index_dir: str = Field("index", description="Index directory")
    faiss_index_path: str = Field("index/code_embeddings.index", description="FAISS index path")
    signature_map_path: str = Field("index/embedding_signature_map.json", description="Signature map path")
    signature_map_path_full: str = Field("index/embedding_full_signature_map.json", description="Full signature map path")
    embedding_metadata_path: str = Field("index/embedding_metadata.json", description="Embedding metadata path")
    embedding_model_name: str = Field("all-MiniLM-L6-v2", description="Embedding model name")
    upload_dir: str = Field("uploaded_code", description="Upload directory")
    java_root_dir: str = Field("uploaded_code", description="Java root directory")
    neo4j_uri: str = Field("bolt://localhost:7687", description="Neo4j URI")
    neo4j_user: str = Field("neo4j", description="Neo4j user")
    neo4j_pass: str = Field(..., description="Neo4j password")
    llm_provider: str = Field("openai", description="LLM provider")
    llm_model: str = Field("gpt-4o-mini", description="LLM model")
    llm_api_base: str = Field(None, description="LLM API base")
    llm_api_key: str = Field(None, description="LLM API key")
    llm_temperature: float = Field(0.2, description="LLM temperature")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        fields = {
            "index_dir": {"env": "INDEX_DIR"},
            "faiss_index_path": {"env": "FAISS_INDEX_PATH"},
            "signature_map_path": {"env": "SIGNATURE_MAP_PATH"},
            "signature_map_path_full": {"env": "SIGNATURE_MAP_PATH_FULL"},
            "embedding_metadata_path": {"env": "EMBEDDING_METADATA_PATH"},
            "embedding_model_name": {"env": "EMBEDDING_MODEL_NAME"},
            "upload_dir": {"env": "UPLOAD_DIR"},
            "java_root_dir": {"env": "JAVA_ROOT_DIR"},
            "neo4j_uri": {"env": "NEO4J_URI"},
            "neo4j_user": {"env": "NEO4J_USER"},
            "neo4j_pass": {"env": "NEO4J_PASS"},
            "llm_provider": {"env": "LLM_PROVIDER"},
            "llm_model": {"env": "LLM_MODEL"},
            "llm_api_base": {"env": "LLM_API_BASE"},
            "llm_api_key": {"env": "LLM_API_KEY"},
            "llm_temperature": {"env": "LLM_TEMPERATURE"},
        }

settings = Settings()

# For backward compatibility, expose old variable names
INDEX_DIR = settings.index_dir
FAISS_INDEX_PATH = settings.faiss_index_path
SIGNATURE_MAP_PATH = settings.signature_map_path
SIGNATURE_MAP_PATH_FULL = settings.signature_map_path_full
EMBEDDING_METADATA_PATH = settings.embedding_metadata_path
EMBEDDING_MODEL_NAME = settings.embedding_model_name
UPLOAD_DIR = settings.upload_dir
JAVA_ROOT_DIR = settings.java_root_dir
NEO4J_URI = settings.neo4j_uri
NEO4J_USER = settings.neo4j_user
NEO4J_PASS = settings.neo4j_pass
LLM_PROVIDER = settings.llm_provider
LLM_MODEL = settings.llm_model
LLM_API_BASE = settings.llm_api_base
LLM_API_KEY = settings.llm_api_key
LLM_TEMPERATURE = settings.llm_temperature
