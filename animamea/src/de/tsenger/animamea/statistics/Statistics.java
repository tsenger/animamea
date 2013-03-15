/**
 *  Copyright 2012, Tobias Senger
 *  
 *  This file is part of animamea.
 *
 *  Animamea is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Animamea is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License   
 *  along with animamea.  If not, see <http://www.gnu.org/licenses/>.
 */
package de.tsenger.animamea.statistics;

/**
 * @author Tobias Senger (tobias@t-senger.de)
 * 
 */
public class Statistics {

	double mean;
	double standardDeviation;
	double variance;

	double sumOfSquares;
	double sum;

	int count;

	public void update(double value) {
		count++;
		this.sum += value;
		this.sumOfSquares += value * value;
		this.mean += (value - mean) / count;
		this.standardDeviation = Math.sqrt((count * sumOfSquares - sum * sum)
				/ (count * (count - 1)));
		this.variance = this.standardDeviation * this.standardDeviation;
	}

	public double getMean() {
		return mean;
	}

	public void setMean(double mean) {
		this.mean = mean;
	}

	public double getStandardDeviation() {
		return standardDeviation;
	}

	public void setStandardDeviation(double standardDeviation) {
		this.standardDeviation = standardDeviation;
	}

	@Override
	public String toString() {

		StringBuilder stringBuilder = new StringBuilder();
		stringBuilder.append("sum: ");
		stringBuilder.append(sum);
		stringBuilder.append("\n");

		stringBuilder.append("sum of x²: ");
		stringBuilder.append(sumOfSquares);
		stringBuilder.append("\n");

		stringBuilder.append("mean: ");
		stringBuilder.append(mean);
		stringBuilder.append("\n");

		stringBuilder.append("stddev: ");
		stringBuilder.append(standardDeviation);
		stringBuilder.append("\n");

		stringBuilder.append("variance: ");
		stringBuilder.append(variance);
		stringBuilder.append("\n");

		return stringBuilder.toString();
	}

}
