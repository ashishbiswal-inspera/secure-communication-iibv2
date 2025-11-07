import { useState } from "react";
import "./App.css";

interface ApiRequest {
  name: string;
  email: string;
}

interface ApiResponse {
  success: boolean;
  message: string;
  data?: ApiRequest;
}

function App() {
  const [response, setResponse] = useState<ApiResponse | null>(null);
  const [loading, setLoading] = useState(false);

  const handleGet = async () => {
    setLoading(true);
    try {
      const res = await fetch("http://localhost:9000/api/get");
      const data: ApiResponse = await res.json();
      setResponse(data);

      // Clear response after 2 seconds
      setTimeout(() => {
        setResponse(null);
      }, 2000);
    } catch (error) {
      console.error("GET request failed:", error);
      setResponse({
        success: false,
        message: "Request failed",
      });
      setTimeout(() => setResponse(null), 2000);
    } finally {
      setLoading(false);
    }
  };

  const handlePost = async () => {
    setLoading(true);
    try {
      const requestBody: ApiRequest = {
        name: "John Doe",
        email: "john.doe@example.com",
      };

      const res = await fetch("http://localhost:9000/api/post", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(requestBody),
      });
      const data: ApiResponse = await res.json();
      setResponse(data);

      // Clear response after 2 seconds
      setTimeout(() => {
        setResponse(null);
      }, 2000);
    } catch (error) {
      console.error("POST request failed:", error);
      setResponse({
        success: false,
        message: "Request failed",
      });
      setTimeout(() => setResponse(null), 2000);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app">
      <h1>React + Go API Test</h1>

      <div className="button-container">
        <button onClick={handleGet} disabled={loading} className="get-button">
          GET Request
        </button>

        <button onClick={handlePost} disabled={loading} className="post-button">
          POST Request
        </button>
      </div>

      {loading && <p className="loading">Loading...</p>}

      {response && (
        <div className={`response ${response.success ? "success" : "error"}`}>
          <h3>Response:</h3>
          <p>
            <strong>Success:</strong> {response.success ? "Yes" : "No"}
          </p>
          <p>
            <strong>Message:</strong> {response.message}
          </p>
          {response.data && <pre>{JSON.stringify(response.data, null, 2)}</pre>}
        </div>
      )}
    </div>
  );
}

export default App;
