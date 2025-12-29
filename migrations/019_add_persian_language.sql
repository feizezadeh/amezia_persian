-- Add Persian language support
INSERT IGNORE INTO languages (code, name, native_name, is_active)
VALUES ('fa', 'Persian', 'فارسی', 1);

-- Basic Persian translations (fallback to English will be used for missing keys)
INSERT IGNORE INTO translations (locale, category, key_name, translation) VALUES
('fa', 'menu', 'dashboard', 'داشبورد'),
('fa', 'menu', 'servers', 'سرورها'),
('fa', 'menu', 'settings', 'تنظیمات'),
('fa', 'menu', 'clients', 'کاربران'),
('fa', 'menu', 'logout', 'خروج'),
('fa', 'auth', 'email', 'ایمیل'),
('fa', 'auth', 'password', 'رمز عبور'),
('fa', 'auth', 'login', 'ورود'),
('fa', 'auth', 'register', 'ثبت نام'),
('fa', 'auth', 'name', 'نام'),
('fa', 'common', 'status', 'وضعیت'),
('fa', 'common', 'actions', 'عملیات'),
('fa', 'form', 'save', 'ذخیره'),
('fa', 'form', 'cancel', 'انصراف');
