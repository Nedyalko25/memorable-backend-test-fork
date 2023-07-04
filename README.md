# Memorable Dashboard Backend TEST

Thank you for applying to Memorable! The purpose of this test is to assess your technical skills in handling tasks that Memorable developers encounter daily.
We are currently developing tools based on AI models to evaluate the cognitive impact of videos and images. These tools require an exceptional user experience to appeal to our clients. Our primary product is offered through a dashboard where users can upload their assets and analyze memorability and saliency metrics.

## Guidelines
- You have access to a very reduced version of the production backend repository. Fork it and follow the instructions in the README to get it up and running.
- If the code at the end doesn't work, we could evaluate it. But it is better if it works.
- Any question would be discussed in the code review meeting, the main part of the test is that conversation.
- The test is not about finishing it, but about how you do it. If you don't finish it, we will discuss what you did and how you would finish it.
- Any suggestions and ideas about thing to improve in the code are welcome. We expect you to be critical with the code.
- All the code in this repo is for this interview proposes. You can change anything you want.

### Objective && Deliverables
- Your task is to implement a new endpoint to change the status of a brand. However, this operation should only be possible if the user making the request is an administrator (isAdmin is true), and has access to the brand in question.
- We need you to make a fork of this repository, and create a PR with the code changes:
    - The code must be in a new branch and pointing to dev branch
    - The change must include the new endpoint and the logic to change the status of the brand
    - A modification in the thunder client configuration (using the thunder client extension ui) with the test of the new endpoint
- diego.medina@memorable.io with the email subject “Tech Test Questions - BackEnd Developer”.

### Evaluation criteria
We’d like you to demonstrate your ability to produce high-quality code. We will focus particularly on:
- Extensibility
- Reusability
- Readability

## App structure

-   src/intelligentSuite: Contains the main app code. Focus mainly in intelligentSuite folder to avoid getting lost in the code. The other folders are common code for all domains (could be reviewed to understand the code, but not necessary).
-   Resolvers: Map graphql endpoint info to what logic needs:
    - They SHOULD NOT contain any business logic.
    - When the service returns void, the resolver should return true.
-   Services: Contain the business logic.
    - They should be endpoint independent. The services should not care if they are being called in GraphQL, Rest or other typescript code.
    - If a method or logic is complex enough, it should be extracted to a different class, and use that class in the service.
    - There SHOULD NOT be database queries in the services, they should only work with repositories or query sets.
    - All permissions checks should be done here. ALWAYS CHECK PERMISSIONS
    - Every external service should be encapsulated in its own class, and not used directly in services
-   Repositories: logic to access the database. Is the infrastructure layer for database access.
-   Entities: Model classes:
    - If they are for endpoint input add Input to the type and annotate with @InputType
    - If they are for endpoint output annotate with @ObjectType and no need to add Output to the type

-   Normal flow. We follow clean architecture in the project. Due to that, we normally have 2 flows:
    - Vertical flow: Each domain has its own resolvers, services, repositories, etc. Then if all is related with our domain, we normally create Resolver -> Service -> Repository/Other Services related with infrastructure
    - Horizontal flow: Different domains (users, products, etc) are in different folders. if we need something from another domain, we inject the other domain service in the constructor of our service.

-   Model modifications:
    - Any entity with the TypeORM @Entity decorator will be automatically added to the database schema.
    - To add new fields to an entity, use the @Column decorator.

\*\* All entities classes must be in an `entities` folder, so they are detected by migrations.

\*\* All resolvers classes must be in a `resolvers` folder and imported into `src/graphql/graphqlSchema.ts`.

\*\* All db operations should be in repositories. All reusable operations should be in query sets.

## Stack

-   [TypeScript](https://www.typescriptlang.org) as the language
-   [TypeORM](https://typeorm.io/#/) as the database ORM
-   [TypeDi](https://github.com/typestack/typedi) as dependency injection container
-   [Apollo](https://www.apollographql.com/docs/) as the graphql server
-   [Type-graphql](https://typegraphql.com/) as the graphql library
-   [aws-sdk](https://docs.aws.amazon.com/sdk-for-javascript/v3/developer-guide/getting-started-nodejs.html) as AWS integration library
-   [DynamoDB mapper](https://www.npmjs.com/package/@aws/dynamodb-data-mapper-annotations) as a DynamoDB ORM
-   [Typegoose](https://typegoose.github.io/typegoose/docs/guides/quick-start-guide) and [Mongoose](https://mongoosejs.com/) as MongoDB ORM
-   [SQS](https://github.com/getlift/lift/blob/master/docs/queue.md) for events queue
-   [Elastic Beanstalk](https://aws.amazon.com/elasticbeanstalk/) as infrastructure manager
-   [Mocha](https://mochajs.org/) as testing framework
-   [Chai](https://www.chaijs.com/) as testing assert framework
-   [ESLint](https://eslint.org) as a linter
-   [Prettier](https://prettier.io) as a formatter
-   [Husky](https://typicode.github.io/husky) as the git hooks manager
-   [Git](https://git-scm.com) as the source control manager
-   [GitHub Actions](https://github.com/features/actions) as the CI/CD manager

## Documentation

[GraphQL schema](schema.gql)

-   To read docs locally: `npm run docs`

## Setup

-   Install node.js and npm, then run `npm install`
-   Install [Docker](https://docs.docker.com/engine/install/) and docker-compose
-   Run `docker-compose up` for the first time, then `docker-compose start` every time you start development
-   Env: `cp .env.example .env` and configure if necessary

### Populate database

-   The init project folder has the creation schema script and a dump of the dev database.
-   Import the dump `dbDump-dev.sql` to your local database using MySQL Workbench or whatever tool you like

## Development

-   Start local server: `npm start`
-   Run build: `npm run build`
-   Run linter: `npm run lint`

## Api usage
1. Install Thunder Client
   [Download VSCode Extension](https://marketplace.visualstudio.com/items?itemName=rangav.vscode-thunder-client)
1. Add memorable-api path in your VSCode Workspace settings in `.vscode/settings.json`.

   Example:

   ```
   {
           ...,
           "thunder-client.customLocation": "$HOME/memorable-backend-test/thunder-client"
   }
   ```


### Main branches

-   `main` (production environment).
-   `dev` (development environment).

All pull requests should be merged into `dev` branch.

