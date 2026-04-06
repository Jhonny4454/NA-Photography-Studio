ALTER TABLE package_reviews
DROP FOREIGN KEY package_reviews_ibfk_2;

ALTER TABLE package_reviews
ADD CONSTRAINT package_reviews_ibfk_2
FOREIGN KEY (user_id) REFERENCES users(id)
ON DELETE CASCADE;