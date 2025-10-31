import React, { useState, useEffect, createContext, useContext } from 'react';

// --- Global Styles for Animations ---
// We add this style tag for animations that are difficult to do with pure Tailwind
// or for JIT-dependent classes like 'animate-in'.
const AppStyles = () => (
  <style>{`
    @keyframes fadeIn {
      from { opacity: 0; }
      to { opacity: 1; }
    }
    @keyframes popIn {
      from { opacity: 0; transform: scale(0.9); }
      to { opacity: 1; transform: scale(1); }
    }
    .modal-backdrop {
      animation: fadeIn 0.3s ease-out forwards;
    }
    .modal-content {
      animation: popIn 0.3s ease-out forwards;
    }
  `}</style>
);


// --- Utility Functions and Components ---

// 1. Context for Authentication
const AuthContext = createContext();

// 2. Custom hook to access auth context
const useAuth = () => useContext(AuthContext);

// Utility for reusable form inputs
const FormInput = ({ label, id, type = 'text', value, onChange, placeholder, required = false, disabled = false, error = null }) => (
  <div className="mb-4">
    <label htmlFor={id} className="block text-sm font-medium text-gray-700 mb-1">
      {label}
    </label>
    <input
      id={id}
      type={type}
      value={value}
      onChange={onChange}
      placeholder={placeholder}
      required={required}
      disabled={disabled}
      className={`w-full p-3 border ${error ? 'border-red-500' : 'border-gray-300'} rounded-lg shadow-sm focus:ring-2 focus:ring-indigo-400 focus:border-transparent transition duration-150 ease-in-out`}
    />
    {error && <p className="mt-1 text-sm text-red-600">{error}</p>}
  </div>
);

// Utility for standard buttons
const Button = ({ onClick, children, type = 'button', disabled = false, className = '' }) => (
  <button
    type={type}
    onClick={onClick}
    disabled={disabled}
    className={`w-full py-3 px-4 font-semibold rounded-lg shadow-md transition-all duration-300 ease-in-out ${
      disabled
        ? 'bg-gray-400 text-gray-700 cursor-not-allowed'
        : 'bg-indigo-600 text-white hover:bg-indigo-700 focus:outline-none focus:ring-4 focus:ring-indigo-300'
    } ${className}`}
  >
    {children}
  </button>
);

// Utility for showing loading state
const LoadingSpinner = () => (
  <div className="flex justify-center items-center p-8">
    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600"></div>
    <span className="ml-3 text-indigo-600">Loading...</span>
  </div>
);

// Utility for displaying server messages/errors
const MessageBox = ({ message, type = 'error', onClose }) => {
  const bgColor = type === 'error' ? 'bg-red-100 border-red-400 text-red-700' : 'bg-green-100 border-green-400 text-green-700';
  const icon = type === 'error' ? '🚨' : '✅';
  
  if (!message) return null;

  return (
    <div className={`p-4 border-l-4 rounded-lg shadow-md mb-4 flex justify-between items-center ${bgColor}`} role="alert">
      <div className="flex items-center">
        <span className="text-xl mr-3">{icon}</span>
        <p className="font-medium text-sm">{message}</p>
      </div>
      {onClose && (
        <button 
          onClick={onClose}
          className="ml-4 text-sm font-semibold p-1 rounded-full hover:bg-opacity-50 transition"
        >
          &times;
        </button>
      )}
    </div>
  );
};

// --- New Reusable StatCard Component ---
const StatCard = ({ title, value, icon }) => (
  <div className="bg-white rounded-xl shadow-lg p-6 flex items-center space-x-4 border border-gray-100 transform transition-transform duration-300 hover:scale-105 hover:shadow-xl">
    <div className="flex-shrink-0 p-3 bg-indigo-100 text-indigo-600 rounded-full">
      {icon}
    </div>
    <div>
      <p className="text-gray-500 font-medium">{title}</p>
      <p className="text-4xl font-bold text-indigo-600 mt-1">{value}</p>
    </div>
  </div>
);

// Reusable Icons
const UsersIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
  </svg>
);

const ClassIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
  </svg>
);

const SubjectIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.246 18 16.5 18c-1.747 0-3.332.477-4.5 1.253" />
  </svg>
);

const MarkIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
  </svg>
);

const MaterialIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
  </svg>
);


// --- AuthProvider (The Core Backend Integration) ---

const AuthProvider = ({ children }) => {
  const [currentUser, setCurrentUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  
  // Base URL for the Node.js backend - MUST match your server.js port!
  const API_BASE_URL = 'https://studysync-1-a5la.onrender.com/api';

  useEffect(() => {
    // Attempt to validate token and fetch user data on load
    const storedUser = JSON.parse(localStorage.getItem('user'));
    if (token && storedUser) {
        setCurrentUser(storedUser);
    } else {
        // If token or user data is missing, clear localStorage just in case
        localStorage.removeItem('token');
        localStorage.removeItem('user');
    }
  }, []); // Run only once on mount

  // Utility function to handle API requests
  const apiRequest = async (endpoint, method = 'GET', data = null, needsAuth = true) => {
    setError(null);
    setIsLoading(true);
    const headers = {
      'Content-Type': 'application/json',
    };

    if (needsAuth && token) {
      headers['x-auth-token'] = token;
    }

    const config = {
      method,
      headers,
      body: data ? JSON.stringify(data) : null,
    };

    try {
      const response = await fetch(`${API_BASE_URL}/${endpoint}`, config);
      const result = await response.json();
      setIsLoading(false);

      if (!response.ok) {
        // Handle 401/403 for unauthorized access
        if (response.status === 401 || response.status === 403) {
            logout(); // Force log out if token is invalid or expired
        }
        throw new Error(result.msg || `API Error: ${response.status}`);
      }
      return result;
    } catch (err) {
      setIsLoading(false);
      setError(err.message || 'An unknown error occurred.');
      throw err;
    }
  };

  // 1. Login function
  const login = async (email, password, navigate) => {
    try {
      const result = await apiRequest('auth/login', 'POST', { email, password }, false);
      
      localStorage.setItem('token', result.token);
      localStorage.setItem('user', JSON.stringify(result.user));
      setToken(result.token);
      setCurrentUser(result.user);
      
      // --- FIX 1: Always navigate to 'home' on login ---
      if (navigate) navigate('home'); // <-- ALWAYS go to 'home'
      
      return true;
    } catch (err) {
      throw err; 
    }
  };

  // 2. Signup function
  const signup = async (name, email, password, navigate, role = 'user', classId = null, classIds = []) => {
    try {
      const payload = { name, email, password, role, classId, classIds };
      const result = await apiRequest('auth/signup', 'POST', payload, false); 
      
      // Admin creating users should not log in as them
      if (currentUser && currentUser.role === 'admin') {
        return true; // Just return success, don't change auth state
      }

      // Public signup
      localStorage.setItem('token', result.token);
      localStorage.setItem('user', JSON.stringify(result.user));
      setToken(result.token);
      setCurrentUser(result.user);
      if (navigate) navigate('home'); // <-- Go to 'home' after signup too
      return true;
    } catch (err) {
      throw err;
    }
  };

  // 3. Logout function
  const logout = (navigate) => {
    setToken(null);
    setCurrentUser(null);
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    if (navigate) navigate('login');
  };

  // 4. Change Password function
  const changePassword = async (oldPassword, newPassword, navigate) => {
    try {
      await apiRequest('auth/change-password', 'POST', { oldPassword, newPassword });
      // If successful, force logout for token renewal/security
      if (navigate) logout(navigate);
      return { success: true, message: 'Password changed successfully. Please log in again.' };
    } catch (err) {
      throw err;
    }
  };

  // --- API GET/FETCH FUNCTIONS ---
  const fetchClasses = () => apiRequest('classes', 'GET');
  const fetchSubjects = () => apiRequest('subjects', 'GET');

  const fetchUsers = () => apiRequest('users', 'GET');
  const fetchMarks = () => apiRequest('marks', 'GET');
  const fetchMaterials = () => apiRequest('materials', 'GET');

  // --- API CRUD FUNCTIONS ---
  const addClass = (name) => apiRequest('classes', 'POST', { name });
  const deleteClass = (id) => apiRequest(`classes/${id}`, 'DELETE');
  
  const addSubject = (name) => apiRequest('subjects', 'POST', { name });
  const deleteSubject = (id) => apiRequest(`subjects/${id}`, 'DELETE');

  const deleteUser = (id) => apiRequest(`users/${id}`, 'DELETE');
  // Pass only necessary fields to backend update
  const updateUser = (id, userData) => apiRequest(`users/${id}`, 'PUT', {
      name: userData.name,
      email: userData.email,
      role: userData.role,
      classId: userData.classId,
      classIds: userData.classIds
  });

  const addMark = (data) => apiRequest('marks', 'POST', data);
  const deleteMark = (id) => apiRequest(`marks/${id}`, 'DELETE');
  // --- ADDED FOR MARK EDIT ---
  const updateMark = (id, data) => apiRequest(`marks/${id}`, 'PUT', data);

  const addMaterial = (data) => apiRequest('materials', 'POST', data);
  const deleteMaterial = (id) => apiRequest(`materials/${id}`, 'DELETE');

  const contextValue = {
    currentUser,
    token,
    isLoading,
    error,
    login,
    signup,
    logout,
    changePassword,
    fetchClasses,
    fetchSubjects,
    addClass,
    deleteClass,
    addSubject,
    deleteSubject,
    fetchUsers,
    deleteUser,
    updateUser,
    fetchMarks,
    addMark,
    deleteMark,
    updateMark, // --- ADDED FOR MARK EDIT ---
    fetchMaterials,
    addMaterial,
    deleteMaterial
  };

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  );
};


// --- Page Components ---

const Header = ({ navigateTo }) => {
  const { currentUser, logout, error, isLoading } = useAuth();
  
  const handleLogout = () => logout(navigateTo);
  
  const navItems = [
    { name: 'Home', page: 'home' },
    { name: 'Change Password', page: 'changePassword' },
  ];

  return (
    <header className="bg-indigo-700 text-white shadow-lg fixed w-full z-10">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <h1 className="text-2xl font-bold tracking-wider">StudySync 📚</h1>
          
          <div className="hidden md:flex items-center space-x-4">
            {currentUser && navItems.map(item => (
              <button 
                key={item.page}
                onClick={() => navigateTo(item.page)}
                className="text-sm font-medium px-3 py-2 rounded-md hover:bg-indigo-600 transition duration-150"
              >
                {item.name}
              </button>
            ))}
            
            {currentUser && (
              <button
                onClick={handleLogout}
                className="bg-red-500 hover:bg-red-600 px-4 py-2 rounded-lg text-sm font-semibold transition duration-150 shadow-md"
                disabled={isLoading}
              >
                Logout ({currentUser.name})
              </button>
            )}
          </div>

          {!currentUser && (
            <div className="flex items-center space-x-4">
              <button 
                onClick={() => navigateTo('login')}
                className="text-sm font-medium px-3 py-2 rounded-md hover:bg-indigo-600 transition duration-150"
              >
                Login
              </button>
              <button 
                onClick={() => navigateTo('signup')}
                className="bg-indigo-500 hover:bg-indigo-600 px-3 py-2 rounded-lg text-sm font-semibold transition duration-150 shadow-md"
              >
                Sign Up
              </button>
            </div>
          )}
        </div>
      </div>
      {(error || isLoading) && (
         <div className="absolute top-16 w-full p-2 bg-yellow-400 text-center text-sm font-medium">
            {isLoading ? 'Processing request...' : error}
         </div>
      )}
    </header>
  );
};

const LoginPage = ({ navigateTo }) => {
  const { login, isLoading, error } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMessage('');
    try {
      await login(email, password, navigateTo);
    } catch (err) {
      setMessage(err.message || 'Login failed.');
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 pt-16">
      <div className="w-full max-w-md p-8 space-y-6 bg-white rounded-xl shadow-2xl border border-gray-100">
        <h2 className="text-3xl font-extrabold text-gray-900 text-center">
          Sign in to StudySync
        </h2>
        <MessageBox message={message} type="error" onClose={() => setMessage('')} />
        <form onSubmit={handleSubmit} className="space-y-4">
          <FormInput
            id="login-email"
            label="Email Address"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="admin@studysync.com"
            required
            disabled={isLoading}
          />
          <FormInput
            id="login-password"
            label="Password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="admin123!"
            required
            disabled={isLoading}
          />
          <Button type="submit" disabled={isLoading}>
            {isLoading ? <LoadingSpinner /> : 'Login'}
          </Button>
        </form>
        <p className="text-center text-sm text-gray-600">
          Don't have an account? 
          <button 
            onClick={() => navigateTo('signup')}
            className="text-indigo-600 hover:text-indigo-500 font-medium ml-1"
          >
            Register here
          </button>
        </p>
        <div className="text-xs text-gray-500 mt-4 text-center">
          <p>Admin Login: admin@studysync.com / admin123!</p>
          <p>Teacher Login: teacher@studysync.com / teacher123!</p>
          <p>Student Login: user@studysync.com / user123!</p>
        </div>
      </div>
    </div>
  );
};

const SignupPage = ({ navigateTo }) => {
  const { signup, isLoading, error } = useAuth();
  const [form, setForm] = useState({ name: '', email: '', password: '' });
  const [message, setMessage] = useState('');

  const handleChange = (e) => {
    setForm({ ...form, [e.target.id.replace('signup-', '')]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMessage('');
    try {
      // NOTE: This signup endpoint automatically logs in.
      await signup(form.name, form.email, form.password, navigateTo);
      setMessage('Registration successful! Redirecting...');
    } catch (err) {
      setMessage(err.message || 'Registration failed.');
    }
  };

  const passwordValidation = (pw) => {
    if (pw.length < 8) return 'Password must be at least 8 characters.';
    if (!/[A-Z]/.test(pw)) return 'Must contain an uppercase letter.';
    if (!/[a-z]/.test(pw)) return 'Must contain a lowercase letter.';
    if (!/[0-9]/.test(pw)) return 'Must contain a number.';
    if (!/[!@#$%^&*()]/.test(pw)) return 'Must contain a symbol (!, @, #, etc).';
    return null;
  };

  const passwordError = form.password && passwordValidation(form.password);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 pt-16">
      <div className="w-full max-w-lg p-8 space-y-6 bg-white rounded-xl shadow-2xl border border-gray-100">
        <h2 className="text-3xl font-extrabold text-gray-900 text-center">
          Create a New Account
        </h2>
        <MessageBox message={message} type={message.includes('successful') ? 'success' : 'error'} onClose={() => setMessage('')} />
        <form onSubmit={handleSubmit} className="space-y-4">
          <FormInput
            id="signup-name"
            label="Full Name"
            type="text"
            value={form.name}
            onChange={handleChange}
            placeholder="John Doe"
            required
            disabled={isLoading}
          />
          <FormInput
            id="signup-email"
            label="Email Address"
            type="email"
            value={form.email}
            onChange={handleChange}
            placeholder="you@example.com"
            required
            disabled={isLoading}
          />
          <FormInput
            id="signup-password"
            label="Password"
            type="password"
            value={form.password}
            onChange={handleChange}
            placeholder="Secure Password"
            required
            disabled={isLoading}
            error={passwordError}
          />
          <p className={`text-xs mt-1 ${passwordError ? 'text-red-500' : 'text-green-500'}`}>
            {passwordError ? `Password strength: ${passwordError}` : 'Password strength: Strong'}
          </p>
          <Button type="submit" disabled={isLoading || !!passwordError}>
            {isLoading ? <LoadingSpinner /> : 'Register'}
          </Button>
        </form>
        <p className="text-center text-sm text-gray-600">
          Already have an account? 
          <button 
            onClick={() => navigateTo('login')}
            className="text-indigo-600 hover:text-indigo-500 font-medium ml-1"
          >
            Login here
          </button>
        </p>
      </div>
    </div>
  );
};


const ChangePasswordPage = ({ navigateTo }) => {
  const { changePassword, isLoading, error } = useAuth();
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [message, setMessage] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMessage('');
    try {
      const result = await changePassword(oldPassword, newPassword, navigateTo);
      setMessage(result.message);
    } catch (err) {
      setMessage(err.message || 'Password change failed.');
    }
  };

  const passwordValidation = (pw) => {
    if (pw.length < 8) return 'Password must be at least 8 characters.';
    return null;
  };

  const passwordError = newPassword && passwordValidation(newPassword);

  return (
    <div className="min-h-screen flex items-start justify-center bg-gray-50 pt-24">
      <div className="w-full max-w-md p-8 space-y-6 bg-white rounded-xl shadow-2xl border border-gray-100">
        <h2 className="text-3xl font-extrabold text-gray-900 text-center">
          Change Password
        </h2>
        <MessageBox message={message} type={message?.includes('successfully') ? 'success' : 'error'} onClose={() => setMessage('')} />
        <form onSubmit={handleSubmit} className="space-y-4">
          <FormInput
            id="old-password"
            label="Current Password"
            type="password"
            value={oldPassword}
            onChange={(e) => setOldPassword(e.target.value)}
            required
            disabled={isLoading}
          />
          <FormInput
            id="new-password"
            label="New Password"
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            required
            disabled={isLoading}
            error={passwordError}
          />
          <p className="text-xs text-gray-500 mt-1">
            Min 8 characters, needs uppercase, lowercase, number, and symbol.
          </p>
          <Button type="submit" disabled={isLoading || !!passwordError || oldPassword === newPassword}>
            {isLoading ? <LoadingSpinner /> : 'Update Password'}
          </Button>
        </form>
      </div>
    </div>
  );
};


// --- Admin Components ---

const AdminManagementTab = ({ navigateTo }) => {
  const { 
    currentUser, 
    isLoading, 
    fetchUsers, 
    deleteUser, 
    updateUser, 
    fetchClasses,
    fetchSubjects,
    addClass,
    deleteClass,
    addSubject,
    deleteSubject,
    signup // Admin uses signup endpoint to create users
  } = useAuth();
  
  const [activeTab, setActiveTab] = useState('users'); // 'users', 'classes', 'subjects'
  const [users, setUsers] = useState([]);
  const [classes, setClasses] = useState([]);
  const [subjects, setSubjects] = useState([]);
  const [managementError, setManagementError] = useState(null);
  const [successMessage, setSuccessMessage] = useState(null);
  const [editUserId, setEditUserId] = useState(null);
  const [editForm, setEditForm] = useState({});
  const [newItemName, setNewItemName] = useState('');
  const [showAddUserModal, setShowAddUserModal] = useState(false);
  const [addUserForm, setAddUserForm] = useState({ name: '', email: '', password: '', role: 'user', classId: '', classIds: [] });

  // Fetch all data
  const fetchData = async () => {
    try {
      setManagementError(null);
      const [usersData, classesData, subjectsData] = await Promise.all([
        fetchUsers(), 
        fetchClasses(), 
        fetchSubjects()
      ]);
      setUsers(usersData);
      setClasses(classesData);
      setSubjects(subjectsData);
    } catch (err) {
      setManagementError(err.message);
    }
  };

  useEffect(() => {
    if (currentUser) {
      fetchData();
    }
  }, [currentUser, activeTab]);

  // --- CRUD Handlers ---

  const handleAddUserSubmit = async (e) => {
    e.preventDefault();
    setManagementError(null);
    if (!addUserForm.name || !addUserForm.email || !addUserForm.password) {
        setManagementError('Name, Email, and Password are required.');
        return;
    }
    try {
        // Use signup API for creation
        await signup(
            addUserForm.name, 
            addUserForm.email, 
            addUserForm.password, 
            null, // No navigation after add
            addUserForm.role,
            addUserForm.classId,
            addUserForm.classIds
        );
        setSuccessMessage('User added successfully.');
        setShowAddUserModal(false);
        // FIX: Resetting form state using the initial object structure
        setAddUserForm({ name: '', email: '', password: '', role: 'user', classId: '', classIds: [] });
        fetchData(); // Refresh list
    } catch (err) {
        setManagementError(err.message);
    }
  };


  const handleDeleteUser = async (id) => {
    // FIX: Compare against currentUser.id, not currentUser._id
    if (id === currentUser.id) {
        setManagementError('Cannot delete yourself.');
        return;
    }
    if (window.confirm('Are you sure you want to delete this user?')) {
      try {
        setManagementError(null);
        await deleteUser(id);
        setSuccessMessage('User deleted successfully.');
        fetchData();
      } catch (err) {
        setManagementError(err.message);
      }
    }
  };

  const handleEditUser = (user) => {
    setEditUserId(user._id);
    setManagementError(null);
    setEditForm({ 
      name: user.name, 
      email: user.email, 
      role: user.role, 
      classId: user.classId, 
      classIds: user.classIds || [] 
    });
  };

  const handleSaveUser = async (e) => {
    e.preventDefault();
    setManagementError(null);
    try {
      // NOTE: We only send fields that are allowed to be updated by the user.
      await updateUser(editUserId, editForm);
      setSuccessMessage('User updated successfully.');
      setEditUserId(null);
      fetchData();
    } catch (err) {
      setManagementError(err.message);
    }
  };

  const handleAddEntity = async (type) => {
    if (!newItemName.trim()) return;
    try {
      setManagementError(null);
      if (type === 'classes') {
        await addClass(newItemName);
      } else {
        await addSubject(newItemName);
      }
      setSuccessMessage(`${type === 'classes' ? 'Class' : 'Subject'} added successfully.`);
      setNewItemName('');
      fetchData();
    } catch (err) {
      setManagementError(err.message);
    }
  };

  const handleDeleteEntity = async (type, id) => {
    if (window.confirm(`Are you sure you want to delete this ${type.slice(0, -1)}?`)) {
      try {
        setManagementError(null);
        if (type === 'classes') {
          await deleteClass(id);
        } else {
          await deleteSubject(id);
        }
        setSuccessMessage(`${type === 'classes' ? 'Class' : 'Subject'} deleted.`);
        fetchData();
      } catch (err) {
        setManagementError(err.message);
      }
    }
  };

  const renderUserTable = () => (
    <div className="mt-4">
        <button
            onClick={() => setShowAddUserModal(true)}
            className="flex items-center px-4 py-2 mb-4 text-sm font-medium text-white bg-green-600 rounded-lg shadow-sm hover:bg-green-700 transition duration-150"
        >
            <span className="text-xl mr-1">+</span> Add New User
        </button>
      <div className="overflow-x-auto shadow-md rounded-lg border">
        <table className="min-w-full divide-y divide-gray-200">
          <thead className="bg-gray-100">
            <tr>
              {['Name', 'Email', 'Role', 'Class/Classes', 'Actions'].map(header => (
                <th key={header} className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">{header}</th>
              ))}
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {users.map(user => (
              <tr key={user._id} className="hover:bg-gray-50 transition duration-150">
                {editUserId === user._id ? (
                  <td colSpan="5" className="p-4 bg-indigo-50">
                    <form onSubmit={handleSaveUser} className="space-y-3">
                        <div className="grid grid-cols-2 gap-4">
                            <FormInput id="name" label="Name" value={editForm.name} onChange={(e) => setEditForm({...editForm, name: e.target.value})} />
                            <FormInput id="email" label="Email" value={editForm.email} onChange={(e) => setEditForm({...editForm, email: e.target.value})} />
                        </div>
                        <div className="grid grid-cols-2 gap-4">
                            <div>
                                <label className="block text-sm font-medium text-gray-700">Role</label>
                                <select value={editForm.role} onChange={(e) => setEditForm({...editForm, role: e.target.value, classId: '', classIds: []})} className="w-full p-2 border rounded-lg">
                                    {['user', 'teacher', 'admin'].map(r => <option key={r} value={r}>{r.toUpperCase()}</option>)}
                                </select>
                            </div>
                            {editForm.role === 'user' && (
                                <div>
                                    <label className="block text-sm font-medium text-gray-700">Assign Class</label>
                                    <select value={editForm.classId || ''} onChange={(e) => setEditForm({...editForm, classId: e.target.value})} className="w-full p-2 border rounded-lg">
                                        <option value="">Select Class</option>
                                        {classes.map(c => <option key={c._id} value={c._id}>{c.name}</option>)}
                                    </select>
                                </div>
                            )}
                        </div>
                        {editForm.role === 'teacher' && (
                            <div className="p-2 border rounded-lg max-h-32 overflow-y-auto bg-white">
                                <label className="block text-sm font-medium text-gray-700 mb-1">Assigned Classes</label>
                                {classes.map(c => (
                                    <label key={c._id} className="inline-flex items-center mr-4 text-xs">
                                        <input 
                                            type="checkbox"
                                            checked={editForm.classIds?.includes(c._id)}
                                            onChange={(e) => {
                                                const newIds = e.target.checked
                                                    ? [...(editForm.classIds || []), c._id]
                                                    : editForm.classIds.filter(id => id !== c._id);
                                                setEditForm({...editForm, classIds: newIds});
                                            }}
                                        />
                                        <span className="ml-2">{c.name}</span>
                                    </label>
                                ))}
                            </div>
                        )}
                        <div className="flex justify-end space-x-3">
                            <button type="button" onClick={() => setEditUserId(null)} className="px-4 py-2 text-sm text-gray-700 bg-white border rounded-lg hover:bg-gray-100">Cancel</button>
                            <button type="submit" className="px-4 py-2 text-sm text-white bg-indigo-600 rounded-lg hover:bg-indigo-700">Save</button>
                        </div>
                    </form>
                  </td>
                ) : (
                  <>
                    <td className="px-6 py-4 whitespace-nowrap">{user.name}</td>
                    <td className="px-6 py-4 whitespace-nowrap">{user.email}</td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${user.role === 'admin' ? 'bg-red-100 text-red-800' : user.role === 'teacher' ? 'bg-blue-100 text-blue-800' : 'bg-green-100 text-green-800'}`}>
                        {user.role}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-xs">
                      {user.role === 'user' && user.classId ? classes.find(c => c._id === user.classId)?.name || 'N/A' :
                       user.role === 'teacher' && user.classIds?.length > 0 ? user.classIds.map(id => classes.find(c => c._id === id)?.name).join(', ') : 'N/A'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium space-x-2">
                      <button onClick={() => handleEditUser(user)} className="text-indigo-600 hover:text-indigo-900">Edit</button>
                      <button onClick={() => handleDeleteUser(user._id)} className="text-red-600 hover:text-red-900" disabled={user.role === 'admin' && users.filter(u => u.role === 'admin').length === 1}>Delete</button>
                    </td>
                  </>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );

  const renderEntityList = (data, type) => (
    <div className="mt-4">
      <div className="flex space-x-2 mb-4">
        <FormInput 
          id={`new-${type}`}
          label={`Add New ${type.slice(0, -1)}`}
          value={newItemName}
          onChange={(e) => setNewItemName(e.target.value)}
          placeholder={`Enter new ${type.slice(0, -1)} name`}
        />
        <Button onClick={() => handleAddEntity(type)} className="w-1/3 self-end">Add</Button>
      </div>
      <ul className="divide-y divide-gray-200 border rounded-lg max-h-96 overflow-y-auto shadow-sm">
        {data.map(item => (
          <li key={item._id} className="flex justify-between items-center p-4 hover:bg-gray-50 bg-white">
            <span className="text-gray-900 font-medium">{item.name}</span>
            <button onClick={() => handleDeleteEntity(type, item._id)} className="text-red-600 hover:text-red-800 text-sm">Delete</button>
          </li>
        ))}
      </ul>
    </div>
  );
  
  const AddUserModal = () => (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 modal-backdrop">
        <div className="bg-white p-8 rounded-xl shadow-2xl w-full max-w-xl modal-content" onClick={(e) => e.stopPropagation()}>
            <h3 className="text-2xl font-bold mb-4">Add New User</h3>
            <MessageBox message={managementError} type="error" onClose={() => setManagementError(null)} />
            <form onSubmit={handleAddUserSubmit} className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                    {/* --- FIX 2: Use (prev => ...) for stable state updates --- */}
                    <FormInput id="name" label="Name" value={addUserForm.name} onChange={(e) => setAddUserForm(prev => ({...prev, name: e.target.value}))} required />
                    <FormInput id="email" label="Email" type="email" value={addUserForm.email} onChange={(e) => setAddUserForm(prev => ({...prev, email: e.target.value}))} required />
                </div>
                <div className="grid grid-cols-2 gap-4">
                    <FormInput id="password" label="Password" type="password" value={addUserForm.password} onChange={(e) => setAddUserForm(prev => ({...prev, password: e.target.value}))} required />
                    <div>
                        <label className="block text-sm font-medium text-gray-700">Role</label>
                        <select value={addUserForm.role} onChange={(e) => setAddUserForm(prev => ({...prev, role: e.target.value, classId: '', classIds: []}))} className="w-full p-3 border rounded-lg">
                            {['user', 'teacher', 'admin'].map(r => <option key={r} value={r}>{r.toUpperCase()}</option>)}
                        </select>
                    </div>
                </div>
                {addUserForm.role === 'user' && (
                    <div>
                        <label className="block text-sm font-medium text-gray-700">Assign Class</label>
                        <select value={addUserForm.classId} onChange={(e) => setAddUserForm(prev => ({...prev, classId: e.target.value}))} className="w-full p-3 border rounded-lg">
                            <option value="">Select Class</option>
                            {classes.map(c => <option key={c._id} value={c._id}>{c.name}</option>)}
                        </select>
                    </div>
                )}
                {addUserForm.role === 'teacher' && (
                    <div className="p-2 border rounded-lg max-h-32 overflow-y-auto">
                        <label className="block text-sm font-medium text-gray-700 mb-1">Assigned Classes</label>
                        {classes.map(c => (
                            <label key={c._id} className="inline-flex items-center mr-4 text-xs">
                                <input 
                                    type="checkbox"
                                    checked={addUserForm.classIds.includes(c._id)}
                                    onChange={(e) => {
                                        const newIds = e.target.checked
                                            ? [...addUserForm.classIds, c._id]
                                            : addUserForm.classIds.filter(id => id !== c._id);
                                        setAddUserForm(prev => ({...prev, classIds: newIds}));
                                    }}
                                />
                                <span className="ml-2">{c.name}</span>
                                    </label>
                                ))}
                            </div>
                        )}
                        <div className="flex justify-end space-x-3 pt-4">
                            <button type="button" onClick={() => setShowAddUserModal(false)} className="px-4 py-2 text-sm text-gray-700 bg-white border rounded-lg hover:bg-gray-100">Cancel</button>
                            <button type="submit" className="px-4 py-2 text-sm text-white bg-green-600 rounded-lg hover:bg-green-700">Create User</button>
                        </div>
                    </form>
                </div>
            </div>
          );


          return (
            <div className="p-6 bg-white rounded-xl shadow-lg">
                {showAddUserModal && <AddUserModal />}
              <h3 className="text-2xl font-bold mb-4 text-gray-800">School Management Console</h3>
              <MessageBox message={managementError} type="error" onClose={() => setManagementError(null)} />
              <MessageBox message={successMessage} type="success" onClose={() => setSuccessMessage(null)} />

              {/* Tabs */}
              <div className="flex border-b border-gray-200 mb-4">
                {['users', 'classes', 'subjects'].map(tab => (
                  <button
                    key={tab}
                    onClick={() => setActiveTab(tab)}
                    className={`px-4 py-2 text-sm font-medium capitalize border-b-2 transition duration-150 ${
                      activeTab === tab
                        ? 'border-indigo-600 text-indigo-600'
                        : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                    }`}
                  >
                    {tab.replace('s', ' ') + ' Management'}
                  </button>
                ))}
              </div>

              {/* Content */}
              {isLoading ? <LoadingSpinner /> : (
                <>
                  {activeTab === 'users' && renderUserTable()}
                  {activeTab === 'classes' && renderEntityList(classes, 'classes')}
                  {activeTab === 'subjects' && renderEntityList(subjects, 'subjects')}
                </>
              )}
            </div>
          );
        };

        const AdminDashboard = ({ navigateTo }) => {
          const [activeTab, setActiveTab] = useState('home'); // 'home', 'management', 'operations'
          const { currentUser } = useAuth();
          
          return (
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 pt-24 min-h-screen">
              <div className="flex border-b border-gray-300 mb-6">
                {['home', 'management', 'operations'].map(tab => (
                  <button
                    key={tab}
                    onClick={() => setActiveTab(tab)}
                    className={`px-6 py-3 text-lg font-semibold capitalize border-b-4 transition duration-200 ${
                      activeTab === tab
                        ? 'border-indigo-600 text-indigo-800 bg-indigo-50'
                        : 'border-transparent text-gray-500 hover:text-gray-700'
                    }`}
                  >
                    {tab === 'home' ? 'Main Home Page' : tab === 'management' ? 'School Management' : 'Consolidated Operations'}
                  </button>
                ))}
              </div>
              
              <div className="mt-6">
                {activeTab === 'home' && <HomePage navigateTo={navigateTo} />}
                {activeTab === 'management' && <AdminManagementTab navigateTo={navigateTo} />}
                {activeTab === 'operations' && <AdminOperationsTab />}
              </div>
            </div>
          );
        };

        const AdminOperationsTab = () => {
            const { fetchMarks, deleteMark, fetchMaterials, deleteMaterial, fetchUsers, isLoading, error } = useAuth();
            const [marks, setMarks] = useState([]);
            const [materials, setMaterials] = useState([]);
            const [users, setUsers] = useState([]);
            const [opError, setOpError] = useState(null);
            const [opSuccess, setOpSuccess] = useState(null);
            const [activeSubTab, setActiveSubTab] = useState('marks'); // 'marks', 'materials'

            const fetchData = async () => {
                try {
                    setOpError(null);
                    const [marksData, materialsData, usersData] = await Promise.all([
                        fetchMarks(),
                        fetchMaterials(),
                        fetchUsers()
                    ]);
                    setMarks(marksData);
                    setMaterials(materialsData);
                    setUsers(usersData);
                } catch (err) {
                    setOpError(err.message);
                }
            };

            useEffect(() => {
                fetchData();
            }, [activeSubTab]);

            const handleDelete = async (type, id) => {
                if (window.confirm(`Are you sure you want to delete this ${type.slice(0, -1)}?`)) {
                    try {
                        setOpError(null);
                        if (type === 'marks') {
                            await deleteMark(id);
                        } else {
                            await deleteMaterial(id);
                        }
                        setOpSuccess(`${type.slice(0, -1)} deleted successfully.`);
                        fetchData();
                    } catch (err) {
                        setOpError(err.message);
                    }
                }
            };

            const getUserName = (id) => users.find(u => (u._id) === id)?.name || 'Unknown';

            const renderMarks = () => (
                <div className="mt-4 overflow-x-auto shadow-md rounded-lg border">
                    <h4 className="text-xl font-semibold mb-3 p-4 bg-gray-50">All Uploaded Marks</h4>
                    <table className="min-w-full divide-y divide-gray-200">
                        <thead className="bg-gray-100">
                            <tr>
                                {['Student', 'Class', 'Subject', 'Marks', 'Teacher', 'Date', 'Action'].map(header => (
                                    <th key={header} className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">{header}</th>
                                ))}
                            </tr>
                        </thead>
                        <tbody className="bg-white divide-y divide-gray-200">
                            {marks.map(mark => (
                                <tr key={mark._id} className="hover:bg-gray-50 transition duration-150">
                                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{mark.studentName}</td>
                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{mark.classId}</td>
                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{mark.subject}</td>
                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{mark.marks}</td>
                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{getUserName(mark.teacherId)}</td>
                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{new Date(mark.createdAt).toLocaleDateString()}</td>
                                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                        <button onClick={() => handleDelete('marks', mark._id)} className="text-red-600 hover:text-red-900">Delete</button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            );

            const renderMaterials = () => (
                <div className="mt-4 overflow-x-auto shadow-md rounded-lg border">
                    <h4 className="text-xl font-semibold mb-3 p-4 bg-gray-50">All Uploaded Study Materials</h4>
                    <table className="min-w-full divide-y divide-gray-200">
                        <thead className="bg-gray-100">
                            <tr>
                                {['Title', 'Class', 'Subject', 'Teacher', 'Link', 'Date', 'Action'].map(header => (
                                    <th key={header} className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">{header}</th>
                                ))}
                            </tr>
                        </thead>
                        <tbody className="bg-white divide-y divide-gray-200">
                            {materials.map(material => (
                                <tr key={material._id} className="hover:bg-gray-50 transition duration-150">
                                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{material.title}</td>
                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{material.classId}</td>
                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{material.subject}</td>
                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{getUserName(material.teacherId)}</td>
                                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                        <a href={material.fileUrl} target="_blank" className="text-indigo-600 hover:text-indigo-900">View File</a>
                                    </td>
                                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{new Date(material.createdAt).toLocaleDateString()}</td>
                                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                        <button onClick={() => handleDelete('materials', material._id)} className="text-red-600 hover:text-red-900">Delete</button>
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            );

            return (
                <div className="p-6 bg-white rounded-xl shadow-lg">
                    <h3 className="text-2xl font-bold mb-4 text-gray-800">Consolidated Operations</h3>
                    <MessageBox message={opError} type="error" onClose={() => setOpError(null)} />
                    <MessageBox message={opSuccess} type="success" onClose={() => setOpSuccess(null)} />

                    {/* Sub Tabs */}
                    <div className="flex border-b border-gray-200 mb-4">
                        {['marks', 'materials'].map(tab => (
                            <button
                                key={tab}
                                onClick={() => setActiveSubTab(tab)}
                                className={`px-4 py-2 text-sm font-medium capitalize border-b-2 transition duration-150 ${
                                    activeSubTab === tab
                                        ? 'border-indigo-600 text-indigo-600'
                                        : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                                }`}
                            >
                                {tab === 'marks' ? 'Student Marks' : 'Study Materials'}
                            </button>
                        ))}
                    </div>

                    {isLoading ? <LoadingSpinner /> : (
                        <>
                            {activeSubTab === 'marks' && renderMarks()}
                            {activeSubTab === 'materials' && renderMaterials()}
                        </>
                    )}
                </div>
            );
        };


        // --- Teacher Components ---

        const TeacherDashboard = ({ navigateTo }) => {
          const { currentUser, fetchClasses } = useAuth();
          const [activeTab, setActiveTab] = useState('home'); // 'home', 'marks', 'materials'
          const [classes, setClasses] = useState([]);

          const loadClasses = async () => {
            try {
                const classesData = await fetchClasses();
                setClasses(classesData);
            } catch (err) {
                // Error handling in context
            }
          };

          useEffect(() => {
            loadClasses();
          }, []);

          const getClassName = (id) => classes.find(c => c._id === id)?.name || id;

          return (
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 pt-24 min-h-screen">
              <div className="flex border-b border-gray-300 mb-6">
                {/* --- FIX: RE-ADD 'marks' TAB --- */}
                {['home', 'marks', 'materials'].map(tab => (
                  <button
                    key={tab}
                    onClick={() => setActiveTab(tab)}
                    className={`px-6 py-3 text-lg font-semibold capitalize border-b-4 transition duration-200 ${
                      activeTab === tab
                        ? 'border-indigo-600 text-indigo-800 bg-indigo-50'
                        : 'border-transparent text-gray-500 hover:text-gray-700'
                    }`}
                  >
                    {tab === 'home' ? 'Home' : tab === 'marks' ? 'Marks Management' : 'Material Upload'}
                  </button>
                ))}
              </div>
              
              <div className="mt-6">
                {activeTab === 'home' && <HomePage navigateTo={navigateTo} />}
                {/* --- FIX: RE-ADD 'marks' RENDER --- */}
                {activeTab === 'marks' && <TeacherMarksTab />}
                {activeTab === 'materials' && <TeacherMaterialsTab />}
              </div>
            </div>
          );
        };

        // --- FIX: RE-ADD TeacherMarksTab component ---
        const TeacherMarksTab = () => {
            const { currentUser, isLoading, fetchUsers, fetchMarks, addMark, deleteMark, updateMark, fetchSubjects, fetchClasses } = useAuth();
            const [marks, setMarks] = useState([]);
            const [users, setUsers] = useState([]);
            const [subjects, setSubjects] = useState([]);
            const [classes, setClasses] = useState([]);
            const [markForm, setMarkForm] = useState({ studentId: '', subject: '', marks: '', classId: '' });
            const [message, setMessage] = useState(null);
            
            // --- EDIT STATE ---
            const [editingMarkId, setEditingMarkId] = useState(null);
            const [editMarkValue, setEditMarkValue] = useState('');

            const assignedClassIds = currentUser.classIds || [];
            const studentsInAssignedClasses = users.filter(u => u.role === 'user' && assignedClassIds.includes(u.classId));

            const fetchData = async () => {
                try {
                    const [usersData, marksData, subjectsData, classesData] = await Promise.all([
                        fetchUsers(), 
                        fetchMarks(), 
                        fetchSubjects(),
                        fetchClasses()
                    ]);
                    setUsers(usersData);
                    setMarks(marksData); // These are *only* the teacher's marks
                    setSubjects(subjectsData);
                    setClasses(classesData);
                } catch (err) {
                    setMessage({ type: 'error', text: err.message });
                }
            };

            useEffect(() => {
                fetchData();
            }, [currentUser]);

            const handleStudentChange = (e) => {
                const studentId = e.target.value;
                const student = users.find(u => u._id === studentId);
                setMarkForm({ 
                    ...markForm, 
                    studentId: studentId, 
                    classId: student ? student.classId : '' // Automatically set classId
                });
            };

            const handleAddMark = async (e) => {
                e.preventDefault();
                setMessage(null);
                if (!markForm.studentId || !markForm.subject || !markForm.marks || !markForm.classId) {
                    setMessage({ type: 'error', text: 'All fields are required.' });
                    return;
                }

                try {
                    await addMark(markForm);
                    setMessage({ type: 'success', text: 'Marks uploaded successfully.' });
                    setMarkForm({ studentId: '', subject: '', marks: '', classId: '' });
                    fetchData();
                } catch (err) {
                    setMessage({ type: 'error', text: err.message });
                }
            };

            const handleDeleteMark = async (id) => {
                if (window.confirm('Are you sure you want to delete this mark entry?')) {
                    try {
                        await deleteMark(id);
                        setMessage({ type: 'success', text: 'Mark deleted successfully.' });
                        fetchData();
                    } catch (err) {
                        setMessage({ type: 'error', text: err.message });
                    }
                }
            };
            
            // --- EDIT HANDLERS ---
            const handleEditClick = (mark) => {
              setEditingMarkId(mark._id);
              setEditMarkValue(mark.marks);
              setMessage(null);
            };
            
            const handleCancelClick = () => {
              setEditingMarkId(null);
              setEditMarkValue('');
            };
            
            const handleSaveMark = async (markId) => {
              setMessage(null);
              try {
                await updateMark(markId, { marks: editMarkValue });
                setMessage({ type: 'success', text: 'Mark updated successfully!' });
                setEditingMarkId(null);
                fetchData(); // Refresh data
              } catch (err) {
                setMessage({ type: 'error', text: err.message });
              }
            };

            const getClassName = (id) => classes.find(c => c._id === id)?.name || id;

            return (
                <div className="p-6 bg-white rounded-xl shadow-lg grid grid-cols-1 lg:grid-cols-3 gap-6">
                    <div className="lg:col-span-1 bg-gray-50 p-4 rounded-lg border h-full">
                        <h4 className="text-xl font-semibold mb-4 text-gray-800">Upload New Marks</h4>
                        {message && <MessageBox message={message.text} type={message.type} onClose={() => setMessage(null)} />}
                        {isLoading ? <LoadingSpinner /> : (
                            <form onSubmit={handleAddMark} className="space-y-4">
                                <label className="block text-sm font-medium text-gray-700">Select Student</label>
                                <select
                                    value={markForm.studentId}
                                    onChange={handleStudentChange}
                                    className="w-full p-3 border rounded-lg shadow-sm"
                                    required
                                    disabled={isLoading}
                                >
                                    <option value="">-- Select Student --</option>
                                    {studentsInAssignedClasses.map(s => (
                                        <option key={s._id} value={s._id}>{s.name} ({getClassName(s.classId)})</option>
                                    ))}
                                </select>
                                
                                <label className="block text-sm font-medium text-gray-700">Select Subject</label>
                                <select
                                    value={markForm.subject}
                                    onChange={(e) => setMarkForm({ ...markForm, subject: e.target.value })}
                                    className="w-full p-3 border rounded-lg shadow-sm"
                                    required
                                >
                                    <option value="">-- Select Subject --</option>
                                    {subjects.map(s => (
                                        <option key={s._id} value={s.name}>{s.name}</option>
                                    ))}
                                </select>

                                <FormInput
                                    id="marks"
                                    label="Mark Value (e.g., 85/100 or A+)"
                                    type="text"
                                    value={markForm.marks}
                                    onChange={(e) => setMarkForm({ ...markForm, marks: e.target.value })}
                                    required
                                    disabled={isLoading}
                                />

                                <Button type="submit" disabled={isLoading}>
                                    {isLoading ? 'Uploading...' : 'Upload Mark'}
                                </Button>
                            </form>
                        )}
                    </div>

                    <div className="lg:col-span-2 p-4">
                        <h4 className="text-xl font-semibold mb-4 text-gray-800">My Uploaded Marks</h4>
                        {isLoading ? <LoadingSpinner /> : (
                            <div className="overflow-x-auto shadow-md rounded-lg border">
                                <table className="min-w-full divide-y divide-gray-200">
                                    <thead className="bg-gray-100">
                                        <tr>
                                            {['Student', 'Class', 'Subject', 'Marks', 'Date', 'Action'].map(header => (
                                                <th key={header} className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">{header}</th>
                                            ))}
                                        </tr>
                                    </thead>
                                    <tbody className="bg-white divide-y divide-gray-200">
                                        {/* FIX: Remove incorrect frontend filter. Backend already filters. */}
                                        {marks.map(m => (
                                            <tr key={m._id} className="hover:bg-gray-50 transition duration-150">
                                                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">{m.studentName}</td>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm">{getClassName(m.classId)}</td>
                                                <td className="px-6 py-4 whitespace-nowrap text-sm">{m.subject}</td>
                                                
                                                {/* --- EDITABLE MARKS CELL --- */}
                                                <td className="px-6 py-4 whitespace-nowrap text-sm font-bold">
                                                  {editingMarkId === m._id ? (
                                                    <input 
                                                      type="text" 
                                                      value={editMarkValue} 
                                                      onChange={(e) => setEditMarkValue(e.target.value)}
                                                      className="w-20 p-1 border rounded shadow-sm"
                                                    />
                                                  ) : (
                                                    m.marks
                                                  )}
                                                </td>
                                                
                                                <td className="px-6 py-4 whitespace-nowrap text-sm">{new Date(m.createdAt).toLocaleDateString()}</td>
                                                
                                                {/* --- EDITABLE ACTIONS CELL --- */}
                                                <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                                  {editingMarkId === m._id ? (
                                                    <>
                                                      <button onClick={() => handleSaveMark(m._id)} className="text-green-600 hover:text-green-900 mr-3">Save</button>
                                                      <button onClick={handleCancelClick} className="text-gray-600 hover:text-gray-900">Cancel</button>
                                                    </>
                                                  ) : (
                                                    <>
                                                      <button onClick={() => handleEditClick(m)} className="text-indigo-600 hover:text-indigo-900 mr-3">Edit</button>
                                                      <button onClick={() => handleDeleteMark(m._id)} className="text-red-600 hover:text-red-900">Delete</button>
                                                    </>
                                                  )}
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </div>
                </div>
            );
        };

        const TeacherMaterialsTab = () => {
            const { currentUser, isLoading, fetchMaterials, addMaterial, deleteMaterial, fetchClasses, fetchSubjects } = useAuth();
            const [materials, setMaterials] = useState([]);
            const [classes, setClasses] = useState([]);
            const [subjects, setSubjects] = useState([]);
            // --- FIX: RE-ADD classId to form state ---
            const [materialForm, setMaterialForm] = useState({ title: '', fileUrl: '', subject: '', classId: '' });
            const [message, setMessage] = useState(null);

            const assignedClassIds = currentUser.classIds || [];
            
            const fetchData = async () => {
                try {
                    const [materialsData, classesData, subjectsData] = await Promise.all([
                        fetchMaterials(), 
                        fetchClasses(), 
                        fetchSubjects()
                    ]);
                    setMaterials(materialsData); // Backend sends only teacher's materials
                    setClasses(classesData);
                    setSubjects(subjectsData);
                } catch (err) {
                    setMessage({ type: 'error', text: err.message });
                }
            };

            useEffect(() => {
                fetchData();
            }, [currentUser]);

            const handleAddMaterial = async (e) => {
                e.preventDefault();
                setMessage(null);
                
                // --- FIX: RE-ADD classId to validation ---
                if (!materialForm.title || !materialForm.classId || !materialForm.subject) {
                    setMessage({ type: 'error', text: 'Title, Class, and Subject are required.' });
                    return;
                }

                try {
                    // --- FIX: Send full form data ---
                    await addMaterial(materialForm);
                    
                    setMessage({ type: 'success', text: 'Material uploaded successfully.' });
                    setMaterialForm({ title: '', fileUrl: '', subject: '', classId: '' }); // Reset form
                    fetchData();
                } catch (err) {
                    setMessage({ type: 'error', text: err.message });
                }
            };

        const handleDeleteMaterial = async (id) => {
            if (window.confirm('Are you sure you want to delete this material?')) {
                try {
                    await deleteMaterial(id);
                    setMessage({ type: 'success', text: 'Material deleted successfully.' });
                    fetchData();
                } catch (err) {
                    setMessage({ type: 'error', text: err.message });
                }
            }
        };

        const getClassName = (id) => classes.find(c => c._id === id)?.name || id;

        return (
            <div className="p-6 bg-white rounded-xl shadow-lg grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div className="lg:col-span-1 bg-gray-50 p-4 rounded-lg border h-full">
                    <h4 className="text-xl font-semibold mb-4 text-gray-800">Upload New Study Material</h4>
                    {message && <MessageBox message={message.text} type={message.type} onClose={() => setMessage(null)} />}
                    {isLoading ? <LoadingSpinner /> : (
                        <form onSubmit={handleAddMaterial} className="space-y-4">
                            <FormInput
                                id="title"
                                label="Title"
                                type="text"
                                value={materialForm.title}
                                onChange={(e) => setMaterialForm({ ...materialForm, title: e.target.value })}
                                required
                            />
                             <FormInput
                                id="fileUrl"
                                label="File Link / URL (Optional)"
                                type="url"
                                value={materialForm.fileUrl}
                                onChange={(e) => setMaterialForm({ ...materialForm, fileUrl: e.target.value })}
                                placeholder="e.g., https://docs.google.com/..."
                            />
                            
                            <label className="block text-sm font-medium text-gray-700">Select Subject</label>
                            <select
                                value={materialForm.subject}
                                onChange={(e) => setMaterialForm({ ...materialForm, subject: e.target.value })}
                                className="w-full p-3 border rounded-lg shadow-sm"
                                required
                            >
                                <option value="">-- Select Subject --</option>
                                {subjects.map(s => (
                                    <option key={s._id} value={s.name}>{s.name}</option>
                                ))}
                            </select>
                            
                            {/* --- FIX: RE-ADD "Assign to Class" dropdown --- */}
                            <label className="block text-sm font-medium text-gray-700">Assign to Class</label>
                            <select
                                value={materialForm.classId}
                                onChange={(e) => setMaterialForm({ ...materialForm, classId: e.target.value })}
                                className="w-full p-3 border rounded-lg shadow-sm"
                                required
                            >
                                <option value="">-- Select Class --</option>
                                {/* --- FIX: THIS IS THE CORRECT LOGIC --- */}
                                {/* Show ALL classes for selection, as requested */}
                                {classes.map(c => (
                                    <option key={c._id} value={c._id}>{c.name}</option>
                                ))}
                            </select>

                            <Button type="submit" disabled={isLoading}>
                                {isLoading ? 'Uploading...' : 'Upload Material'}
                            </Button>
                        </form>
                    )}
                </div>

                <div className="lg:col-span-2 p-4">
                    <h4 className="text-xl font-semibold mb-4 text-gray-800">My Uploaded Materials</h4>
                    {isLoading ? <LoadingSpinner /> : (
                        <div className="overflow-x-auto shadow-md rounded-lg border">
                            <table className="min-w-full divide-y divide-gray-200">
                                <thead className="bg-gray-100">
                                    <tr>
                                        {['Title', 'Class', 'Subject', 'Link', 'Date', 'Action'].map(header => (
                                            <th key={header} className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">{header}</th>
                                        ))}
                                    </tr>
                                </thead>
                                <tbody className="bg-white divide-y divide-gray-200">
                                    {/* FIX: Remove incorrect frontend filter. Backend already filters. */}
                                    {materials.map(m => (
                                        <tr key={m._id} className="hover:bg-gray-50 transition duration-150">
                                            <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">{m.title}</td>
                                            <td className="px-6 py-4 whitespace-nowrap text-sm">{getClassName(m.classId)}</td>
                                            <td className="px-6 py-4 whitespace-nowrap text-sm">{m.subject}</td>
                                            <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                                <a href={m.fileUrl} target="_blank" className="text-indigo-600 hover:text-indigo-900">View</a>
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap text-sm">{new Date(m.createdAt).toLocaleDateString()}</td>
                                            <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                                <button onClick={() => handleDeleteMaterial(m._id)} className="text-red-600 hover:text-red-900">Delete</button>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>
            </div>
        );
    };


    // --- Student Components ---

    const UserDashboard = () => {
        const { currentUser, isLoading, fetchMarks, fetchMaterials, fetchClasses } = useAuth();
        const [marks, setMarks] = useState([]);
        const [materials, setMaterials] = useState([]);
        const [classes, setClasses] = useState([]);
        const [dashError, setDashError] = useState(null);

        const fetchData = async () => {
            try {
                setDashError(null);
                const [marksData, materialsData, classesData] = await Promise.all([
                    fetchMarks(), 
                    fetchMaterials(),
                    fetchClasses()
                ]);
                setMarks(marksData);
                setMaterials(materialsData);
                setClasses(classesData);
            } catch (err) {
                setDashError(err.message);
            }
        };

        useEffect(() => {
            fetchData();
        }, [currentUser]);

        const getClassName = (id) => classes.find(c => c._id === id)?.name || id;

        const renderMarks = () => (
            <div className="p-6 bg-white rounded-xl shadow-lg">
                <h4 className="text-xl font-bold mb-4 text-indigo-700">My Marks</h4>
                <div className="overflow-x-auto shadow-md rounded-lg border">
                    <table className="min-w-full divide-y divide-gray-200">
                        <thead className="bg-indigo-50">
                            <tr>
                                {['Subject', 'Marks', 'Uploaded Date'].map(header => (
                                    <th key={header} className="px-6 py-3 text-left text-xs font-medium text-indigo-700 uppercase tracking-wider">{header}</th>
                                ))}
                            </tr>
                        </thead>
                        <tbody className="bg-white divide-y divide-gray-200">
                            {marks.map(m => (
                                <tr key={m._id} className="hover:bg-gray-50 transition duration-150">
                                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">{m.subject}</td>
                                    <td className="px-6 py-4 whitespace-nowrap text-sm font-bold text-green-600">{m.marks}</td>
                                    <td className="px-6 py-4 whitespace-nowrap text-sm">{new Date(m.createdAt).toLocaleDateString()}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
                {marks.length === 0 && <p className="text-gray-500 mt-4">No marks have been uploaded yet.</p>}
            </div>
        );

        const renderMaterials = () => (
            <div className="p-6 bg-white rounded-xl shadow-lg">
                <h4 className="text-xl font-bold mb-4 text-indigo-700">Study Materials for {getClassName(currentUser.classId)}</h4>
                <ul className="divide-y divide-gray-200 border rounded-lg shadow-sm">
                    {materials.map(m => (
                        <li key={m._id} className="py-4 px-6 flex justify-between items-center hover:bg-gray-50 transition duration-150">
                            <div>
                                <p className="text-base font-semibold text-gray-900">{m.title}</p>
                                <p className="text-sm text-gray-500">{m.subject}</p>
                                <p className="text-xs text-gray-400 mt-1">Uploaded: {new Date(m.createdAt).toLocaleDateString()}</p>
                            </div>
                            <a 
                                href={m.fileUrl} 
                                target="_blank" 
                                className="text-indigo-600 hover:text-indigo-800 font-medium px-3 py-1 border border-indigo-200 rounded-lg transition"
                            >
                                View
                            </a>
                        </li>
                    ))}
                </ul>
                {materials.length === 0 && <p className="text-gray-500 mt-4">No study materials found for your class.</p>}
            </div>
        );

        return (
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 pt-24 min-h-screen">
                <h2 className="text-3xl font-extrabold text-gray-900 mb-6">Student Dashboard - Class {getClassName(currentUser.classId) || 'Unassigned'}</h2>
                {dashError && <MessageBox message={dashError} type="error" onClose={() => setDashError(null)} />}
                {isLoading ? <LoadingSpinner /> : (
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                        {renderMarks()}
                        {renderMaterials()}
                    </div>
                )}
            </div>
        );
    };
    
// --- New, Enhanced Home Page ---
// This component replaces the old "HomeIntro" and provides role-based stats
const HomePage = ({ navigateTo }) => {
  const { 
    currentUser, 
    fetchUsers, fetchClasses, fetchSubjects,
    fetchMarks, fetchMaterials 
  } = useAuth();
  
  const [stats, setStats] = useState(null);
  const [isLoadingStats, setIsLoadingStats] = useState(true);

  useEffect(() => {
    const loadStats = async () => {
      setIsLoadingStats(true);
      try {
        if (currentUser.role === 'admin') {
          const [usersData, classesData, subjectsData] = await Promise.all([
            fetchUsers(), fetchClasses(), fetchSubjects()
          ]);
          setStats({
            val1: usersData.length, label1: 'Total Users', icon1: <UsersIcon />,
            val2: classesData.length, label2: 'Total Classes', icon2: <ClassIcon />,
            val3: subjectsData.length, label3: 'Total Subjects', icon3: <SubjectIcon />,
          });
        } else if (currentUser.role === 'teacher') {
          const [marksData, materialsData, classesData] = await Promise.all([
            fetchMarks(), fetchMaterials(), fetchClasses()
          ]);
          const assignedClassNames = currentUser.classIds
            .map(id => classesData.find(c => c._id === id)?.name)
            .filter(Boolean)
            .join(', ');
          
          setStats({
            val1: currentUser.classIds.length, label1: `Your Classes`, icon1: <ClassIcon />,
            // --- FIX 1: Remove redundant frontend filter. Backend already filters. ---
            val2: marksData.length, label2: 'Marks Uploaded', icon2: <MarkIcon />,
            val3: materialsData.length, label3: 'Materials Posted', icon3: <MaterialIcon />,
          });
        } else { // Student
          const [marksData, materialsData, classesData] = await Promise.all([
            fetchMarks(), fetchMaterials(), fetchClasses()
          ]);
          const myClass = classesData.find(c => c._id === currentUser.classId)?.name;
          setStats({
            val1: myClass || 'No Class', label1: 'Your Class', icon1: <ClassIcon />,
            val2: marksData.length, label2: 'Your Marks', icon2: <MarkIcon />, // fetchMarks is already filtered by student ID
            val3: materialsData.length, label3: 'Your Materials', icon3: <MaterialIcon />, // fetchMaterials is also filtered
          });
        }
      } catch (e) {
        console.error("Failed to load home stats", e);
      }
      setIsLoadingStats(false);
    };
    loadStats();
  }, [currentUser]);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 pt-24 min-h-screen">
      {/* Welcome Header */}
      <div className="p-8 bg-white rounded-xl shadow-lg mb-8 border border-gray-100">
        <h2 className="text-3xl font-extrabold text-gray-900 mb-2">
          Welcome back, {currentUser.name}!
        </h2>
        <p className="text-lg text-gray-600">
          You are logged in as a <span className="font-semibold capitalize text-indigo-600">{currentUser.role}</span>.
        </p>
      </div>

      {/* Stats Grid */}
      {isLoadingStats ? (
        <LoadingSpinner />
      ) : (
        stats && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <StatCard title={stats.label1} value={stats.val1} icon={stats.icon1} />
            <StatCard title={stats.label2} value={stats.val2} icon={stats.icon2} />
            <StatCard title={stats.label3} value={stats.val3} icon={stats.icon3} />
          </div>
        )
      )}

      {/* Navigation Grid (The old HomeIntro) */}
      <div className="p-6 bg-white rounded-xl shadow-lg border border-gray-100">
        <h3 className="text-2xl font-bold text-gray-800 mb-4">Application Overview</h3>
        <p className="text-gray-600 mb-6">
          Use the buttons below to quickly navigate to your main dashboard area based on your role:
        </p>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <button 
            onClick={() => navigateTo('adminDashboard')} 
            className="p-6 text-left bg-indigo-50 rounded-lg border border-indigo-200 hover:bg-indigo-100 transition duration-150 disabled:opacity-50 disabled:cursor-not-allowed" 
            disabled={currentUser.role !== 'admin'}
          >
            <h4 className="font-semibold text-lg text-indigo-700">Admin Console</h4>
            <p className="text-sm text-indigo-600">Full CRUD for Users, Classes, and Subjects.</p>
          </button>
          <button 
            onClick={() => navigateTo('teacherDashboard')} 
            className="p-6 text-left bg-blue-50 rounded-lg border border-blue-200 hover:bg-blue-100 transition duration-150 disabled:opacity-50 disabled:cursor-not-allowed" 
            disabled={currentUser.role !== 'teacher'}
          >
            <h4 className="font-semibold text-lg text-blue-700">Teacher Management</h4>
            <p className="text-sm text-blue-600">Upload Marks and Study Materials for assigned classes.</p>
          </button>
          <button 
            onClick={() => navigateTo('userDashboard')} 
            className="p-6 text-left bg-green-50 rounded-lg border border-green-200 hover:bg-green-100 transition duration-150 disabled:opacity-50 disabled:cursor-not-allowed" 
            disabled={currentUser.role !== 'user'}
          >
            <h4 className="font-semibold text-lg text-green-700">Student View</h4>
            <p className="text-sm text-green-600">View assigned tasks, marks, and class materials.</p>
          </button>
        </div>
      </div>
    </div>
  );
};


    // --- App Structure ---

    const AppContent = () => {
      // FIX: Page state is now correctly inside a component
      const [page, setPage] = useState('login');
      const navigateTo = (pageName) => {
        setPage(pageName);
      };
      
      const { currentUser, token, isLoading } = useAuth();

      // Redirect logic: If logged in, always go to home route
      useEffect(() => {
          if (token && currentUser && (page === 'login' || page === 'signup')) {
              // On initial login, go to 'home'
              navigateTo('home');
          }
          // If not logged in and on a protected route, go to login
          if (!token && !currentUser && page !== 'login' && page !== 'signup') {
              navigateTo('login');
          }
      }, [token, currentUser]);


      if (isLoading && !currentUser) return <LoadingSpinner />;
      
      if (!token || !currentUser) {
        // Unauthenticated view
        return (
          <>
            <AppStyles />
            <Header navigateTo={navigateTo} />
            {page === 'signup' ? <SignupPage navigateTo={navigateTo} /> : <LoginPage navigateTo={navigateTo} />}
          </>
        );
      }

      // --- FIX: Stricter Role-Based Routing ---
      // Determine the user's correct default dashboard component
      let DefaultDashboard = UserDashboard;
      if (currentUser.role === 'admin') DefaultDashboard = AdminDashboard;
      else if (currentUser.role === 'teacher') DefaultDashboard = TeacherDashboard;

      let ContentComponent;
      switch (page) {
        case 'adminDashboard':
            ContentComponent = currentUser.role === 'admin' ? AdminDashboard : DefaultDashboard;
            break;
        case 'teacherDashboard':
            ContentComponent = currentUser.role === 'teacher' ? TeacherDashboard : DefaultDashboard;
            break;
        case 'userDashboard':
            ContentComponent = currentUser.role === 'user' ? UserDashboard : DefaultDashboard;
            break;
        case 'changePassword':
            ContentComponent = ChangePasswordPage;
            break;
        case 'home':
            ContentComponent = HomePage; // Use new enhanced Home Page
            break;
        default:
          // Default to user's appropriate dashboard
          ContentComponent = DefaultDashboard;
      }
      
      return (
        <>
          <AppStyles />
          <Header navigateTo={navigateTo} />
          <ContentComponent navigateTo={navigateTo} />
        </>
      );
    };


    // --- Main Export ---

    const App = () => (
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    );

    export default App;