class User < ApplicationRecord
  include Devise::JWT::RevocationStrategies::Allowlist

  has_many :allowlisted_jwts, dependent: :destroy

  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable, :trackable,
         :jwt_authenticatable, jwt_revocation_strategy: self

  def jwt(jti)
    allowlisted_jwts.find_by!(jti: jti)
  end

  def active_jwts
    allowlisted_jwts.where("exp > ?", Time.current).map do |jwt|
      {
        jti: jwt.jti,
        expires_at: jwt.exp,
        user_agent: jwt.aud
      }
    end
  end

  def delete_jwt(jti)
    jwt = jwt(jti)
    jwt.destroy
  end

  def delete_all_jwts
    allowlisted_jwts.destroy_all
  end
end
