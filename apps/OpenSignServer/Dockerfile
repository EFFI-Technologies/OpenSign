# Use an official Node runtime as the base image
FROM node:20

# Set the working directory inside the container
WORKDIR /usr/src/app

# Copy package.json and package-lock.json first to leverage Docker cache
COPY ./package*.json ./

# Install application dependencies without running the prepare script
RUN npm install --no-prepare

# (Optional) Update npm to the latest version
RUN npm install -g npm@latest

# Copy the current directory contents into the container
COPY ./ .

# Make port 80 available to the world outside this container
EXPOSE 80

# Run the application
ENTRYPOINT ["npm", "start"]
