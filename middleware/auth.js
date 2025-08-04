const checkPermission = (pool) => async (req, res, next) => {
  const adminId = req.session.adminId;
  const adminRole = req.session.adminRole;
  const section = req.permissionSection; // We'll set this in the route

  if (adminRole === 'owner') return next();

  try {
    const permResult = await pool.query(
      'SELECT * FROM admin_permissions WHERE admin_id = $1 AND allowed_section = $2',
      [adminId, section]
    );

    if (permResult.rows.length > 0) return next();

    const requestResult = await pool.query(
      'SELECT * FROM access_requests WHERE admin_id = $1 AND requested_section = $2 AND status = $3',
      [adminId, section, 'pending']
    );

    res.render('admin/access-denied', {
      section,
      requestSent: requestResult.rows.length > 0,
      adminRole: req.session.adminRole
    });
  } catch (err) {
    console.error("Permission check error:", err);
    res.status(500).send("Server error during permission check.");
  }
};

const requireAdminLogin = (req, res, next) => {
  if (!req.session.isAdmin) return res.redirect('/monitor_admin');
  res.locals.adminRole = req.session.adminRole;
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
};

const requireOwner = (req, res, next) => {
  if (req.session.adminRole !== 'owner') {
    return res.status(403).send('Forbidden: You do not have permission to access this page.');
  }
  next();
};

// A helper to set the section name before checking permission
const setPermissionSection = (section) => (req, res, next) => {
    req.permissionSection = section;
    next();
};

module.exports = {
    checkPermission,
    requireAdminLogin,
    requireOwner,
    setPermissionSection
};