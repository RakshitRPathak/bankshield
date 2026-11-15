.PHONY: install seed test eval holdout serve check docker
install: ; python3 -m pip install -r requirements.txt
seed:    ; python3 -m bankshield seed
test:    ; python3 -m pytest -q tests
eval:    ; python3 eval/run_eval.py
holdout: ; python3 eval/run_eval.py --questions eval/holdout.jsonl --min 0
serve:   ; python3 -m bankshield serve
check: seed test eval
docker:  ; docker build -t bankshield:2.0.0 .
