# Convenience targets. `./kavach` is the primary entry point.
.PHONY: demo replay doctor serve clean docker docker-demo test

demo:        ; ./kavach demo
replay:      ; ./kavach replay
doctor:      ; ./kavach doctor
serve:       ; ./kavach serve
clean:       ; ./kavach clean
test:        ; ./kavach replay   # offline, deterministic smoke test

docker:      ; docker build -t kavachforge:latest .
docker-demo: ; ./kavach --docker demo
