import sys

def main():
    if len(sys.argv)<2 or sys.argv[1] not in ('prepare','train','predict','dashboard'):
        raise SystemExit('Usage: python -m soc_ai {prepare|train|predict|dashboard} [options]')
    command=sys.argv.pop(1)
    if command=='prepare': from .prepare import main as run
    elif command=='train': from .train import main as run
    elif command=='predict': from .predict import main as run
    else: from .dashboard import main as run
    run()

if __name__=='__main__': main()
