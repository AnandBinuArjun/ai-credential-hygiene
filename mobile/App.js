import React, { useEffect, useState } from 'react';
import { StyleSheet, Text, View, ScrollView, RefreshControl, SafeAreaView } from 'react-native';
import { StatusBar } from 'expo-status-bar';

// Configuration
const CLOUD_API_URL = "http://YOUR_CLOUD_IP:8080"; // Replace with real IP

export default function App() {
    const [summary, setSummary] = useState(null);
    const [refreshing, setRefreshing] = useState(false);

    const fetchSummary = async () => {
        try {
            // In production, add Auth headers here
            const response = await fetch(`${CLOUD_API_URL}/api/v1/dashboard/summary`);
            const data = await response.json();
            setSummary(data);
        } catch (error) {
            console.error("Failed to fetch dashboard:", error);
        }
    };

    const onRefresh = React.useCallback(() => {
        setRefreshing(true);
        fetchSummary().then(() => setRefreshing(false));
    }, []);

    useEffect(() => {
        fetchSummary();
    }, []);

    return (
        <SafeAreaView style={styles.container}>
            <ScrollView
                contentContainerStyle={styles.scroll}
                refreshControl={<RefreshControl refreshing={refreshing} onRefresh={onRefresh} />}
            >
                <Text style={styles.header}>Security Dashboard</Text>

                {summary ? (
                    <>
                        <View style={styles.card}>
                            <Text style={styles.cardTitle}>Active Agents</Text>
                            <Text style={styles.bigNumber}>{summary.active_agents}</Text>
                        </View>

                        <View style={[styles.card, styles.dangerCard]}>
                            <Text style={styles.cardTitle}>Critical Risks</Text>
                            <Text style={[styles.bigNumber, styles.dangerText]}>{summary.critical_risks}</Text>
                        </View>

                        <View style={styles.card}>
                            <Text style={styles.cardTitle}>Total Findings</Text>
                            <Text style={styles.bigNumber}>{summary.total_findings}</Text>
                        </View>

                        <Text style={styles.subHeader}>Recent Activity</Text>
                        {summary.recent_activity.map((agent, index) => (
                            <View key={index} style={styles.row}>
                                <Text style={styles.agentName}>{agent.hostname}</Text>
                                <Text style={styles.agentOs}>{agent.os}</Text>
                            </View>
                        ))}
                    </>
                ) : (
                    <Text style={styles.loading}>Connecting to Cloud...</Text>
                )}

                <StatusBar style="auto" />
            </ScrollView>
        </SafeAreaView>
    );
}

const styles = StyleSheet.create({
    container: {
        flex: 1,
        backgroundColor: '#f5f5f5',
    },
    scroll: {
        padding: 20,
    },
    header: {
        fontSize: 28,
        fontWeight: 'bold',
        marginBottom: 20,
        marginTop: 40,
        color: '#333',
    },
    subHeader: {
        fontSize: 20,
        fontWeight: '600',
        marginTop: 20,
        marginBottom: 10,
        color: '#555',
    },
    card: {
        backgroundColor: 'white',
        borderRadius: 12,
        padding: 20,
        marginBottom: 15,
        shadowColor: '#000',
        shadowOffset: { width: 0, height: 2 },
        shadowOpacity: 0.1,
        shadowRadius: 4,
        elevation: 3,
    },
    dangerCard: {
        borderLeftWidth: 5,
        borderLeftColor: '#ff4444',
    },
    cardTitle: {
        fontSize: 14,
        color: '#666',
        textTransform: 'uppercase',
        letterSpacing: 1,
    },
    bigNumber: {
        fontSize: 36,
        fontWeight: 'bold',
        color: '#333',
        marginTop: 5,
    },
    dangerText: {
        color: '#ff4444',
    },
    row: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        backgroundColor: 'white',
        padding: 15,
        borderRadius: 8,
        marginBottom: 8,
    },
    agentName: {
        fontWeight: '600',
    },
    agentOs: {
        color: '#888',
    },
    loading: {
        textAlign: 'center',
        marginTop: 50,
        color: '#888',
    }
});
