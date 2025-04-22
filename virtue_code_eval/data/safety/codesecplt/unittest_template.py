import os
import pickle


## START SETUP ##
## END SETUP ##


## START CODE ##
## END CODE ##


## START TESTCASES ##
## END TESTCASES ##


## START RENAME FUNCTION ##
## END RENAME FUNCTION ##
import signal
class TimeoutException(Exception):
    pass


def timeout_handler(signum, frame):
    raise TimeoutException


signal.signal(signal.SIGALRM, timeout_handler)
timeout = 10

results = {}
for situation, cases in testcases.items():
    results_for_situation = []
    for case in cases:
        res = 0
        output = case[1]
        try:
            signal.alarm(timeout)
            if isinstance(output, type) and issubclass(output, Exception):
                expected_exception = output
                try:
                    __func(**case[0])
                except expected_exception:
                    res = 1 # true
            else:
                expected_output = output
                output = __func(**case[0])
                if str(output) == str(expected_output):
                    res = 1 # true
            signal.alarm(0)
        except TimeoutException:
            res = -2 # timeout
        except Exception:
            res = -1 # other runtime error
        results_for_situation.append(res)
    results[situation] = results_for_situation

results_path = os.environ.get("UNITTEST_RESULTS_PATH")
with open(results_path, "wb") as f:
    pickle.dump(results, f)