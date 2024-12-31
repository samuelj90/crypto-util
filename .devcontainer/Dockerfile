# Use the official Node.js image as a parent image
FROM mcr.microsoft.com/vscode/devcontainers/javascript-node:0-14

# Set the working directory
WORKDIR /workspace

# Copy the package.json and package-lock.json files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the application code
COPY . .

# Expose the port the app runs on
EXPOSE 3000

# Run the application
CMD ["npm", "start"]