import { Navigate, Outlet } from 'react-router-dom';
import { useAuth } from '../context/auth';

const ProtectedRoute = ({ allowedRoles, children }) => {
  const { user, token, verified } = useAuth();
  if (!token) return <Navigate to="/login" replace />;
  if (!verified) return <div role="status" className="p-8">Checking your session…</div>;
  if (allowedRoles && (!user || !allowedRoles.includes(user.role.toLowerCase()))) {
    return <Navigate to="/dashboard" replace />;
  }
  return children || <Outlet />;
};
export default ProtectedRoute;
