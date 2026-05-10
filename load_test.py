# load_test.py - run this while your Render API is live
import requests
import threading
import time

API_URL = "https://ml-url-api.onrender.com/predict"
TEST_URL = "https://google.com"
RESULTS = []

def send_request(user_id):
    start = time.time()
    try:
        response = requests.post(
            API_URL,
            json={"url": TEST_URL},
            timeout=30
        )
        elapsed = time.time() - start
        RESULTS.append({
            "user": user_id,
            "status": response.status_code,
            "result": response.json().get("result"),
            "time": round(elapsed, 2)
        })
        print(f"User {user_id}: {response.json().get('result')} ({elapsed:.2f}s)")
    except Exception as e:
        print(f"User {user_id}: FAILED - {e}")

# Simulate 10 concurrent users
threads = []
for i in range(10):
    t = threading.Thread(target=send_request, args=(i+1,))
    threads.append(t)

print("Starting load test with 10 concurrent users...")
start_all = time.time()

for t in threads:
    t.start()
for t in threads:
    t.join()

total_time = time.time() - start_all
print(f"\nAll requests completed in {total_time:.2f}s")
print(f"Successful: {len([r for r in RESULTS if r.get('status') == 200])}/10")
avg_time = sum(r['time'] for r in RESULTS) / len(RESULTS) if RESULTS else 0
print(f"Average response time: {avg_time:.2f}s")