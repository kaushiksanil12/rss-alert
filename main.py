import sys
from config import load_config
from runner import Runner

def main():
    cfg = load_config("sources.yaml")
    if not cfg.sources:
        print("No sources configured. Exiting.")
        sys.exit(1)
        
    runner = Runner(cfg)
    runner.run()

if __name__ == "__main__":
    main()
