import { redirect } from "next/navigation";

// The scan console moved to /scan when the UI was rebuilt.
export default function DashboardRedirect() {
  redirect("/scan");
}
