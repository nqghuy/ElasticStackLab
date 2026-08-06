import os
import yaml
from dataclasses import dataclass 

@dataclass
class ElasticConfig:
    base_url: str 
    kibana_url: str
    verify_ssl: bool
    username: str
    password: str = ""

    @property 
    def auth(self) -> tuple[str, str]:
        return (self.username, self.password)

@dataclass
class VictimConfig:
    hostname: str
    username: str

@dataclass
class RuleWaitConfig:
    poll_interval_sec: int 
    unchanged_limit: int

@dataclass
class Settings:
    elastic: ElasticConfig
    victim: VictimConfig
    rule_wait: RuleWaitConfig

def _load_env_file(env_path: str) -> None:
    if not os.path.exists(env_path):
        return
    with open(env_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())

def load_settings(config_path: str = "config.yaml", env_path=".env") -> Settings:
    _load_env_file(env_path)
    with open(config_path) as f:
        raw = yaml.safe_load(f)
    password = os.environ.get("ELASTIC_PASSWORD")  
    if not password:
        raise RuntimeError(
            "Miss ELASTIC_PASSWORD in .env path"
        )

    elastic_raw = raw["elastic"]
    elastic = ElasticConfig(
        base_url = elastic_raw['base_url'],
        kibana_url = elastic_raw['kibana_url'],
        verify_ssl = elastic_raw['verify_ssl'],
        username = elastic_raw.get('username', 'elastic'),
        password = password
    )

    victim = VictimConfig(**raw['victim'])
    rule_wait = RuleWaitConfig(**raw['rule_wait'])

    return Settings(elastic=elastic, victim=victim, rule_wait=rule_wait)

if __name__ == "__main__":
    settings = load_settings()
    print("Elastic base_url:", settings.elastic.base_url)
    print("Kibana url:", settings.elastic.kibana_url)
    print("Victim:", settings.victim.hostname, settings.victim.username)
    print("Password loaded:", "***" if settings.elastic.password else "MISSING")
