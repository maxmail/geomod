const { Sequelize, DataTypes } = require('sequelize');
const sequelize = require('../config/database'); // ✅ Ensure correct import

const User = sequelize.define('User', {
  id: {
    type: DataTypes.UUID,
    defaultValue: Sequelize.UUIDV4,
    primaryKey: true,
  },
  name: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
    validate: { isEmail: true },
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  role: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  trialEndDate: {
    type: DataTypes.DATE,
    allowNull: true,
  },
  termsAccepted: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: false
  },
  termsAcceptedDate: {
    type: DataTypes.DATE,
    allowNull: true
  }
}, {
  timestamps: true, // ✅ Ensures createdAt and updatedAt fields are included
});

module.exports = User; // ✅ Ensure User model is exported
