import { useState } from "react";
import { Button } from "@/components/ui/button";
import { getServerInfoFromLocation } from "@/lib/secureClient";

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
  const { port, serverUrl } = getServerInfoFromLocation();

  const handleGet = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/get");
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

      const res = await fetch("/api/post", {
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
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-purple-900 to-slate-950 flex items-center justify-center p-8">
      <div className="max-w-2xl w-full space-y-8">
        {/* Header */}
        <div className="text-center space-y-3">
          <h1 className="text-5xl font-bold bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-600 bg-clip-text text-transparent">
            React + Go API - Served from Go!
          </h1>
          <p className="text-slate-400">
            Test your API endpoints (Auto-reload enabled sure)
          </p>
          <div className="mt-4 p-4 bg-slate-800/50 border border-slate-700 rounded-lg text-sm">
            <p className="text-slate-300">
              <span className="font-semibold text-cyan-400">Server:</span>{" "}
              {serverUrl}
            </p>
            <p className="text-slate-300">
              <span className="font-semibold text-cyan-400">Port:</span> {port}
            </p>
          </div>
        </div>

        {/* Buttons */}
        <div className="flex gap-4 justify-center">
          <Button
            onClick={handleGet}
            disabled={loading}
            variant="default"
            size="lg"
            className="bg-green-600 hover:bg-green-700 text-white"
          >
            GET Request
          </Button>

          <Button
            onClick={handlePost}
            disabled={loading}
            variant="default"
            size="lg"
            className="bg-blue-600 hover:bg-blue-700 text-white"
          >
            POST Request
          </Button>
        </div>

        {/* Loading */}
        {loading && (
          <div className="text-center">
            <p className="text-slate-400 animate-pulse">Loading...</p>
          </div>
        )}

        {/* Response */}
        {response && (
          <div
            className={`p-6 rounded-xl border-2 backdrop-blur-sm animate-in fade-in duration-300 ${
              response.success
                ? "bg-green-950/30 border-green-500 text-green-100"
                : "bg-red-950/30 border-red-500 text-red-100"
            }`}
          >
            <h3 className="text-xl font-bold mb-4">Response:</h3>
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <span className="font-semibold text-slate-300">Success:</span>
                <span
                  className={`px-2 py-1 rounded text-sm font-bold ${
                    response.success
                      ? "bg-green-500/20 text-green-300"
                      : "bg-red-500/20 text-red-300"
                  }`}
                >
                  {response.success ? "✓ Yes" : "✗ No"}
                </span>
              </div>
              <div>
                <span className="font-semibold text-slate-300">Message: </span>
                <span className="text-white">{response.message}</span>
              </div>
              {response.data && (
                <div>
                  <span className="font-semibold text-slate-300 block mb-2">
                    Data:
                  </span>
                  <pre className="bg-black/40 border border-slate-700 p-4 rounded-lg overflow-x-auto text-sm text-cyan-300">
                    {JSON.stringify(response.data, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
