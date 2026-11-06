ALTER TABLE user_devices
  DROP CONSTRAINT user_devices_platform_check,
  ADD CONSTRAINT user_devices_platform_check CHECK (platform IN ('android', 'ios', 'web'));
