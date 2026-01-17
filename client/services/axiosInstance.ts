import axios from "axios";

export const baseURL = process.env.NEXT_PUBLIC_BASEURL;

const axiosInstance = axios.create({
  baseURL,
  withCredentials: true,
});

let isRefreshing = false;
let failedQueue: Array<{
  resolve: (value: unknown) => void;
  reject: (reason?: any) => void;
}> = [];

const processQueue = (error: any) => {
  failedQueue.forEach(prom => {
    error ? prom.reject(error) : prom.resolve(null);
  });
  failedQueue = [];
};

axiosInstance.interceptors.response.use(
  (response) => response,

  async (error) => {
    const originalRequest = error.config;

    console.log("[Axios Interceptor] Response error:", {
      status: error.response?.status,
      url: originalRequest?.url,
      hasRetried: originalRequest?._retry
    });

    if (error.response?.status === 401 && !originalRequest._retry) {
      console.log("[Axios Interceptor] 401 detected - initiating refresh flow");
      
      if (isRefreshing) {
        console.log("[Axios Interceptor] Already refreshing - queueing request");
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        })
          .then(() => {
            console.log("[Axios Interceptor] Retrying queued request:", originalRequest.url);
            return axiosInstance(originalRequest);
          })
          .catch(err => Promise.reject(err));
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        console.log("[Axios Interceptor] Calling POST /auth/refresh-token");
        await axiosInstance.post("/auth/refresh-token");
        
        console.log("[Axios Interceptor] Refresh successful - processing queue");
        processQueue(null);
        
        console.log("[Axios Interceptor] Retrying original request:", originalRequest.url);
        return axiosInstance(originalRequest);
      } catch (refreshError) {
        console.error("[Axios Interceptor] Refresh failed - redirecting to login");
        processQueue(refreshError);
        
        if (typeof window !== "undefined") {
          window.location.href = "/login";
        }
        
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);

export default axiosInstance;
