import axios from 'axios';

const mlServiceUrl = process.env.ML_SERVICE_URL || 'http://localhost:8001';

export async function getMLVerdict(content: string, labels: string[]): Promise<{ label: string; score: number } | null> {
  try {
    const response = await axios.post(`${mlServiceUrl}/scan`, {
      text: content,
      labels: labels,
    });

    if (response.data && response.data.labels && response.data.scores) {
      const highestScoreIndex = response.data.scores.indexOf(Math.max(...response.data.scores));
      return {
        label: response.data.labels[highestScoreIndex],
        score: response.data.scores[highestScoreIndex],
      };
    }
    return null;
  } catch (error) {
    console.error('Error calling ML service:', error);
    return null;
  }
}
