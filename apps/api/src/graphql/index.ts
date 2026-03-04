/**
 * GraphQL Server (GraphQL Yoga + Hono)
 *
 * Integration of GraphQL Yoga with Hono for the V3 API.
 * Creates per-request DataLoader context to prevent N+1 queries.
 */

import { createYoga } from 'graphql-yoga';
import { schema } from './resolvers';
import { createLoaders } from './dataLoaders';

// Create Yoga instance with per-request DataLoader context
export const yoga = createYoga({
    schema,
    graphqlEndpoint: '/graphql',
    landingPage: true,
    graphiql: {
        title: 'Rinjani V3 GraphQL',
    },
    context: () => ({
        loaders: createLoaders(),
    }),
});

// Export for mounting in Hono
export { schema };
