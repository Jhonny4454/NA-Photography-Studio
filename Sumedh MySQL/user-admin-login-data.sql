-- Table for portfolio images
CREATE TABLE IF NOT EXISTS `portfolio_images` (
  `id` int NOT NULL AUTO_INCREMENT,
  `photographer_id` int NOT NULL,
  `image_url` varchar(500) NOT NULL,
  `location` varchar(255) DEFAULT NULL,
  `shoot_date` date DEFAULT NULL,
  `description` text,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `photographer_id` (`photographer_id`),
  CONSTRAINT `portfolio_images_ibfk_1` FOREIGN KEY (`photographer_id`) REFERENCES `photographers` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Add profile_image column to photographers table
ALTER TABLE `photographers` ADD COLUMN `profile_image` varchar(500) DEFAULT NULL;