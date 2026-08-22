export const metadata = {
  title: "Sign In — Cognitive Log Investigation Platform",
  description: "Sign in to the Cognitive Log Investigation Platform",
};

export default function LoginLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  // Render children directly — the login page provides its own html/body
  return children;
}
