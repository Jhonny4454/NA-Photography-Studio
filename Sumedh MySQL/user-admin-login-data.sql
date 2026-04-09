ALTER TABLE user_packages
DROP FOREIGN KEY user_packages_ibfk_2,
ADD CONSTRAINT user_packages_ibfk_2
FOREIGN KEY (package_id)
REFERENCES packages(package_id)
ON DELETE CASCADE;