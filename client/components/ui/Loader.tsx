import React from "react";



export const Loader: React.FC<LoaderProps> = ({
  size = 24,
  color = "currentColor",
  thickness = 2,
  className = "",
  label = "Loading",
}) => {
  return (
    <span
      role="status"
      aria-label={label}
      className={className}
      style={{
        display: "inline-block",
        width: size,
        height: size,
        border: `${thickness}px solid ${color}`,
        borderTopColor: "transparent",
        borderRadius: "50%",
        animation: "loader-spin 0.8s linear infinite",
      }}
    />
  );
};
