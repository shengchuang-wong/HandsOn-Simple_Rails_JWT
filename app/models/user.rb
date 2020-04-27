class User < ApplicationRecord
  hash_secure_password
  mount_uploader :avatar, AvatarUploader
  validates :email, presence: true, uniqueness: true
  validates :email, format: { with: URI::MailTo::EMAIL_REGEXP }
  validates :username, presense: true, uniqueness: true
  validates :password, length: { minimum: 6 }, if: -> { new_records? || !password.nil? }
end
